import hashlib
import hmac
import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from organizations.models import Membership, Organization

from . import crypto
from .models import Project, WebhookDelivery, WebhookEndpoint
from .webhooks import SyncHTTPTransport, emit_webhook, sign_payload

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


def make_project(owner, organization, name="prod"):
    salt = crypto.generate_salt()
    key = crypto.derive_key(PASSPHRASE, salt)
    project = Project.objects.create(
        owner=owner,
        organization=organization,
        public_id=Project.new_public_id(),
        name=name,
    )
    project.default_environment.salt = salt
    project.default_environment.verifier = crypto.make_verifier(key)
    project.default_environment.save(update_fields=["salt", "verifier"])
    return project, key


class WebhookSigningTests(APITestCase):
    """Test HMAC-SHA256 signing of webhook payloads."""

    def test_payload_signing(self):
        """Test that payloads are signed correctly with HMAC-SHA256."""
        secret = "webhook-secret-key"
        payload = {"event": "secret.created", "key": "api-key"}
        signature = sign_payload(secret, payload)
        self.assertIsInstance(signature, str)
        self.assertEqual(len(signature), 64)

    def test_signature_deterministic(self):
        """Test that the same payload produces the same signature."""
        secret = "webhook-secret-key"
        payload = {"event": "secret.created", "key": "api-key"}
        sig1 = sign_payload(secret, payload)
        sig2 = sign_payload(secret, payload)
        self.assertEqual(sig1, sig2)

    def test_signature_changes_with_payload(self):
        """Test that different payloads produce different signatures."""
        secret = "webhook-secret-key"
        payload1 = {"event": "secret.created"}
        payload2 = {"event": "secret.deleted"}
        sig1 = sign_payload(secret, payload1)
        sig2 = sign_payload(secret, payload2)
        self.assertNotEqual(sig1, sig2)

    def test_signature_changes_with_secret(self):
        """Test that different secrets produce different signatures."""
        payload = {"event": "secret.created"}
        sig1 = sign_payload("secret1", payload)
        sig2 = sign_payload("secret2", payload)
        self.assertNotEqual(sig1, sig2)

    def test_signature_is_sha256_hex(self):
        """Test that signature matches direct HMAC computation."""
        secret = "webhook-secret"
        payload = {"key": "value"}
        payload_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        expected = hmac.new(
            secret.encode(),
            payload_json.encode(),
            hashlib.sha256,
        ).hexdigest()
        signature = sign_payload(secret, payload)
        self.assertEqual(signature, expected)


class WebhookEndpointTests(APITestCase):
    """Test WebhookEndpoint model and queries."""

    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.org = Organization.objects.create(name="Test Org", slug="test-org")
        Membership.objects.create(
            organization=self.org, user=self.user, role=Membership.ROLE_OWNER
        )

    def test_create_endpoint(self):
        """Test creating a webhook endpoint."""
        endpoint = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks",
            secret="webhook-secret",
            events=["secret.created", "secret.deleted"],
            active=True,
        )
        self.assertEqual(endpoint.organization, self.org)
        self.assertEqual(endpoint.url, "https://example.com/webhooks")
        self.assertEqual(endpoint.secret, "webhook-secret")
        self.assertEqual(endpoint.events, ["secret.created", "secret.deleted"])
        self.assertTrue(endpoint.active)

    def test_endpoint_inactive(self):
        """Test that inactive endpoints are created correctly."""
        endpoint = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks",
            secret="webhook-secret",
            events=["secret.created"],
            active=False,
        )
        self.assertFalse(endpoint.active)

    def test_endpoint_empty_events(self):
        """Test endpoint with empty events list."""
        endpoint = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks",
            secret="webhook-secret",
            events=[],
        )
        self.assertEqual(endpoint.events, [])


class WebhookDeliveryTests(APITestCase):
    """Test WebhookDelivery model and status tracking."""

    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.org = Organization.objects.create(name="Test Org", slug="test-org")
        Membership.objects.create(
            organization=self.org, user=self.user, role=Membership.ROLE_OWNER
        )
        self.endpoint = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks",
            secret="webhook-secret",
            events=["secret.created"],
        )

    def test_create_delivery(self):
        """Test creating a webhook delivery record."""
        payload = {"event": "secret.created", "key": "test"}
        delivery = WebhookDelivery.objects.create(
            endpoint=self.endpoint,
            event_type="secret.created",
            payload=payload,
            status=WebhookDelivery.STATUS_PENDING,
        )
        self.assertEqual(delivery.endpoint, self.endpoint)
        self.assertEqual(delivery.event_type, "secret.created")
        self.assertEqual(delivery.payload, payload)
        self.assertEqual(delivery.status, WebhookDelivery.STATUS_PENDING)

    def test_delivery_success(self):
        """Test recording a successful delivery."""
        payload = {"event": "secret.created"}
        delivery = WebhookDelivery.objects.create(
            endpoint=self.endpoint,
            event_type="secret.created",
            payload=payload,
            status=WebhookDelivery.STATUS_SUCCESS,
            response_status=200,
            response_body="OK",
        )
        self.assertEqual(delivery.status, WebhookDelivery.STATUS_SUCCESS)
        self.assertEqual(delivery.response_status, 200)

    def test_delivery_failed(self):
        """Test recording a failed delivery."""
        payload = {"event": "secret.created"}
        delivery = WebhookDelivery.objects.create(
            endpoint=self.endpoint,
            event_type="secret.created",
            payload=payload,
            status=WebhookDelivery.STATUS_FAILED,
            error_message="Connection timeout",
        )
        self.assertEqual(delivery.status, WebhookDelivery.STATUS_FAILED)
        self.assertEqual(delivery.error_message, "Connection timeout")


class SyncHTTPTransportTests(APITestCase):
    """Test the SyncHTTPTransport delivery mechanism."""

    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.org = Organization.objects.create(name="Test Org", slug="test-org")
        Membership.objects.create(
            organization=self.org, user=self.user, role=Membership.ROLE_OWNER
        )
        self.endpoint = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks",
            secret="webhook-secret",
            events=["secret.created"],
        )
        self.transport = SyncHTTPTransport()

    @patch("vault.webhooks.requests.post")
    def test_successful_delivery(self, mock_post):
        """Test successful HTTP delivery to endpoint."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Accepted"
        mock_post.return_value = mock_response

        payload = {"event": "secret.created", "key": "test"}
        delivery = self.transport.send(self.endpoint, "secret.created", payload)

        self.assertEqual(delivery.status, WebhookDelivery.STATUS_SUCCESS)
        self.assertEqual(delivery.response_status, 200)
        self.assertEqual(delivery.response_body, "Accepted")
        self.assertIsNotNone(delivery.delivered_at)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://example.com/webhooks")
        self.assertIn("X-Signature-256", kwargs["headers"])
        self.assertIn("X-Event-Type", kwargs["headers"])
        self.assertEqual(kwargs["headers"]["X-Event-Type"], "secret.created")

    @patch("vault.webhooks.requests.post")
    def test_failed_delivery_http_error(self, mock_post):
        """Test delivery with HTTP error response."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        payload = {"event": "secret.created"}
        delivery = self.transport.send(self.endpoint, "secret.created", payload)

        self.assertEqual(delivery.status, WebhookDelivery.STATUS_FAILED)
        self.assertEqual(delivery.response_status, 500)

    @patch("vault.webhooks.requests.post")
    def test_failed_delivery_exception(self, mock_post):
        """Test delivery with network exception."""
        mock_post.side_effect = Exception("Connection refused")

        payload = {"event": "secret.created"}
        delivery = self.transport.send(self.endpoint, "secret.created", payload)

        self.assertEqual(delivery.status, WebhookDelivery.STATUS_FAILED)
        self.assertIn("Connection refused", delivery.error_message)

    @patch("vault.webhooks.requests.post")
    def test_signature_in_headers(self, mock_post):
        """Test that signature is included in request headers."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = ""
        mock_post.return_value = mock_response

        payload = {"event": "secret.created"}
        expected_signature = sign_payload(self.endpoint.secret, payload)

        self.transport.send(self.endpoint, "secret.created", payload)

        args, kwargs = mock_post.call_args
        actual_signature = kwargs["headers"]["X-Signature-256"]
        self.assertEqual(actual_signature, expected_signature)


class EmitWebhookTests(APITestCase):
    """Test webhook emission for secret lifecycle events."""

    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.org = Organization.objects.create(name="Test Org", slug="test-org")
        Membership.objects.create(
            organization=self.org, user=self.user, role=Membership.ROLE_OWNER
        )

    def test_emit_to_active_endpoint(self):
        """Test emitting event to active endpoint."""
        endpoint = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks",
            secret="secret",
            events=["secret.created"],
            active=True,
        )

        with patch.object(SyncHTTPTransport, "send") as mock_send:
            mock_delivery = WebhookDelivery(
                endpoint=endpoint,
                event_type="secret.created",
                payload={"key": "test"},
                status=WebhookDelivery.STATUS_SUCCESS,
            )
            mock_send.return_value = mock_delivery

            payload = {"key": "test"}
            deliveries = emit_webhook(self.org.id, "secret.created", payload)

            self.assertEqual(len(deliveries), 1)
            mock_send.assert_called_once()

    def test_skip_inactive_endpoint(self):
        """Test that inactive endpoints are skipped."""
        WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks",
            secret="secret",
            events=["secret.created"],
            active=False,
        )

        with patch.object(SyncHTTPTransport, "send") as mock_send:
            payload = {"key": "test"}
            deliveries = emit_webhook(self.org.id, "secret.created", payload)

            self.assertEqual(len(deliveries), 0)
            mock_send.assert_not_called()

    def test_skip_unsubscribed_event(self):
        """Test that endpoints not subscribed to event are skipped."""
        endpoint = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks",
            secret="secret",
            events=["secret.deleted"],
            active=True,
        )

        with patch.object(SyncHTTPTransport, "send") as mock_send:
            payload = {"key": "test"}
            deliveries = emit_webhook(self.org.id, "secret.created", payload)

            self.assertEqual(len(deliveries), 0)
            mock_send.assert_not_called()

    def test_multiple_endpoints(self):
        """Test emitting to multiple endpoints."""
        endpoint1 = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks1",
            secret="secret1",
            events=["secret.created"],
            active=True,
        )
        endpoint2 = WebhookEndpoint.objects.create(
            organization=self.org,
            url="https://example.com/webhooks2",
            secret="secret2",
            events=["secret.created"],
            active=True,
        )

        with patch.object(SyncHTTPTransport, "send") as mock_send:
            mock_delivery = WebhookDelivery(
                status=WebhookDelivery.STATUS_SUCCESS,
            )
            mock_send.return_value = mock_delivery

            payload = {"key": "test"}
            deliveries = emit_webhook(self.org.id, "secret.created", payload)

            self.assertEqual(len(deliveries), 2)
            self.assertEqual(mock_send.call_count, 2)

    def test_no_endpoints(self):
        """Test emitting when no endpoints exist."""
        payload = {"key": "test"}
        deliveries = emit_webhook(self.org.id, "secret.created", payload)
        self.assertEqual(len(deliveries), 0)
