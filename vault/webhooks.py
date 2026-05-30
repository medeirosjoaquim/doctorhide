import json
import hmac
import hashlib
from datetime import datetime

from django.utils import timezone

try:
    import requests
except ImportError:
    requests = None

from .models import WebhookDelivery, WebhookEndpoint


def sign_payload(secret: str, payload: dict) -> str:
    """Create HMAC-SHA256 signature for webhook payload.

    Signature is computed over the JSON-serialized payload with deterministic
    key ordering. The signature is returned as a hex string suitable for an
    X-Signature-256 header."""
    payload_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    signature = hmac.new(
        secret.encode(),
        payload_json.encode(),
        hashlib.sha256,
    ).hexdigest()
    return signature


class WebhookTransport:
    """Abstract transport for webhook delivery. Subclasses implement send()."""

    def send(self, endpoint: WebhookEndpoint, event_type: str, payload: dict) -> WebhookDelivery:
        """Send a webhook to an endpoint and record the delivery.

        Returns a WebhookDelivery instance with status and response details."""
        raise NotImplementedError


class SyncHTTPTransport(WebhookTransport):
    """Synchronous HTTP delivery (queue-ready: use signal handlers to dispatch via async backend)."""

    def send(self, endpoint: WebhookEndpoint, event_type: str, payload: dict) -> WebhookDelivery:
        """POST the signed payload to the endpoint URL and record the delivery."""
        if requests is None:
            raise RuntimeError("requests library is required for webhook delivery")

        signature = sign_payload(endpoint.secret, payload)
        headers = {
            "Content-Type": "application/json",
            "X-Signature-256": signature,
            "X-Event-Type": event_type,
        }
        payload_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))

        delivery = WebhookDelivery.objects.create(
            endpoint=endpoint,
            event_type=event_type,
            payload=payload,
            status=WebhookDelivery.STATUS_PENDING,
        )

        try:
            response = requests.post(
                endpoint.url,
                data=payload_json,
                headers=headers,
                timeout=10,
            )
            delivery.response_status = response.status_code
            delivery.response_body = response.text[:2000]
            if 200 <= response.status_code < 300:
                delivery.status = WebhookDelivery.STATUS_SUCCESS
            else:
                delivery.status = WebhookDelivery.STATUS_FAILED
        except Exception as e:
            delivery.status = WebhookDelivery.STATUS_FAILED
            delivery.error_message = str(e)[:500]

        delivery.delivered_at = timezone.now()
        delivery.save()
        return delivery


def get_transport() -> WebhookTransport:
    """Get the configured webhook transport.

    By default returns SyncHTTPTransport. In production with async backend,
    signal handlers should wrap this to dispatch to a queue instead."""
    return SyncHTTPTransport()


def emit_webhook(organization_id: int, event_type: str, payload: dict) -> list[WebhookDelivery]:
    """Emit a webhook event to all active endpoints in the organization.

    Returns a list of WebhookDelivery objects for each endpoint. This is
    called by signal handlers when secrets are created/updated/deleted."""
    endpoints = WebhookEndpoint.objects.filter(
        organization_id=organization_id,
        active=True,
    )

    if not endpoints.exists():
        return []

    transport = get_transport()
    deliveries = []
    for endpoint in endpoints:
        if event_type in endpoint.events:
            delivery = transport.send(endpoint, event_type, payload)
            deliveries.append(delivery)

    return deliveries


def emit_secret_rotated(secret) -> list[WebhookDelivery]:
    """Emit secret.rotated event for a rotated secret."""
    payload = {
        "event": "secret.rotated",
        "key": secret.key,
        "project_id": secret.project.public_id,
        "payload_type": secret.payload_type,
        "created_at": secret.created_at.isoformat(),
        "updated_at": secret.updated_at.isoformat(),
    }
    return emit_webhook(secret.project.organization_id, "secret.rotated", payload)


def emit_secret_soft_deleted(secret) -> list[WebhookDelivery]:
    """Emit secret.deleted event for a soft-deleted secret."""
    payload = {
        "event": "secret.deleted",
        "key": secret.key,
        "project_id": secret.project.public_id,
        "created_at": secret.created_at.isoformat(),
        "deleted_at": secret.deleted_at.isoformat() if secret.deleted_at else None,
    }
    return emit_webhook(secret.project.organization_id, "secret.deleted", payload)
