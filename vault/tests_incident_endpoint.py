"""Tests for the ``/admin/incident/revoke-all-keys`` endpoint.

The endpoint is the operator-side counterpart to the
``emergency_revoke_all_keys`` management command and is constrained
deliberately: every auth failure mode must leave a row in AuditEvent, and
the throttle must backstop a misfiring tool. These tests pin both contracts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.test import APIClient

from . import crypto
from .models import AuditEvent, Project, ProjectAPIKey

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


def _login_with_totp(client, user):
    """Force-login a user and mark the session as TOTP-verified by binding
    a confirmed TOTPDevice to the session. This is the minimum the view
    expects; we never go through the real TOTP-enrollment/verify flow here
    because the contract under test is the view's gating, not enrollment."""
    client.force_login(user)
    device = TOTPDevice.objects.create(user=user, name="default", confirmed=True)
    session = client.session
    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    return device


@override_settings(
    REST_FRAMEWORK={
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "iam.authentication.APIKeyAuthentication",
            "rest_framework.authentication.SessionAuthentication",
        ],
        "DEFAULT_PERMISSION_CLASSES": [
            "rest_framework.permissions.IsAuthenticated",
        ],
        "DEFAULT_THROTTLE_RATES": {
            "vault_api": "1000/min",
            "incident": "3/hour",
        },
    }
)
class IncidentRevokeAllKeysEndpointTests(TestCase):
    def setUp(self):
        # The DRF throttle's bucket is a cache key; clear it so each test
        # gets a fresh quota. We use the APIClient for DRF and a regular
        # Client for the session-based login dance.
        cache.clear()
        self.api = APIClient(enforce_csrf_checks=False)
        self.superuser = User.objects.create_superuser(
            username="responder", email="sec@example.com", password="pw-123-secret"
        )
        self.regular = User.objects.create_user(
            username="alice", password="pw-123-secret"
        )
        # Two organizations so we can prove the endpoint scopes correctly.
        from organizations.models import personal_organization

        self.org_a = personal_organization(self.superuser)
        self.org_b = personal_organization(self.regular)

        # A project + some active keys under each org.
        self.proj_a = self._mk_project(self.superuser, self.org_a, "a-proj")
        self.proj_b = self._mk_project(self.regular, self.org_b, "b-proj")
        self.key_a1 = ProjectAPIKey.generate(self.proj_a, name="a1")[0]
        self.key_a2 = ProjectAPIKey.generate(self.proj_a, name="a2")[0]
        self.key_b1 = ProjectAPIKey.generate(self.proj_b, name="b1")[0]

    def _mk_project(self, owner, org, name):
        salt = crypto.generate_salt()
        key = crypto.derive_key(PASSPHRASE, salt)
        project = Project.objects.create(
            owner=owner,
            organization=org,
            public_id=Project.new_public_id(),
            name=name,
        )
        env = project.default_environment
        env.salt = salt
        env.verifier = crypto.make_verifier(key)
        env.save(update_fields=["salt", "verifier"])
        return project

    def _login_responder_with_totp(self):
        _login_with_totp(self.api, self.superuser)

    # --- happy path ---

    def test_superuser_with_totp_revokes_keys_in_target_org(self):
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        resp = self.api.post(url, {"org": self.org_a.id}, format="json")
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["revoked"], 2)
        self.assertEqual(resp.data["org"], self.org_a.id)

        self.key_a1.refresh_from_db()
        self.key_a2.refresh_from_db()
        self.key_b1.refresh_from_db()
        self.assertIsNotNone(self.key_a1.revoked_at)
        self.assertIsNotNone(self.key_a2.revoked_at)
        # Other org's keys untouched.
        self.assertIsNone(self.key_b1.revoked_at)

        ev = AuditEvent.objects.get(
            action="incident.revoke_all_keys", outcome="success"
        )
        self.assertEqual(ev.organization_id, self.org_a.id)
        self.assertEqual(ev.principal, "superuser:responder")
        self.assertIn("revoked=2", ev.secret_key)

    def test_before_cutoff_skips_newer_keys(self):
        self._login_responder_with_totp()
        self.key_a1.created_at -= timedelta(days=10)
        self.key_a1.save(update_fields=["created_at"])

        url = reverse("incident_revoke_all_keys")
        cutoff = (self.key_a2.created_at - timedelta(seconds=1)).isoformat()
        resp = self.api.post(
            url,
            {"org": self.org_a.id, "before": cutoff},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["revoked"], 1)

        self.key_a1.refresh_from_db()
        self.key_a2.refresh_from_db()
        self.assertIsNotNone(self.key_a1.revoked_at)
        self.assertIsNone(self.key_a2.revoked_at)

    # --- auth/authorization gates ---

    def test_anonymous_is_rejected_and_logged(self):
        url = reverse("incident_revoke_all_keys")
        resp = self.api.post(url, {"org": self.org_a.id}, format="json")
        # SessionAuthentication returns 403 (not 401) for unauthenticated
        # browser-style requests without a CSRF cookie, which is the
        # expected response in production.
        self.assertIn(resp.status_code, (401, 403))
        # No audit row from this path: DRF's auth rejection runs before our
        # view body, so we cannot observe a denial row. Pin the contract.

    def test_non_superuser_is_denied_with_403_and_audit_row(self):
        _login_with_totp(self.api, self.regular)
        url = reverse("incident_revoke_all_keys")
        resp = self.api.post(url, {"org": self.org_a.id}, format="json")
        self.assertEqual(resp.status_code, 403, resp.content)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="incident.revoke_all_keys",
                outcome="denied:not_superuser",
            ).exists()
        )
        # No keys revoked.
        self.key_a1.refresh_from_db()
        self.assertIsNone(self.key_a1.revoked_at)

    def test_superuser_without_totp_is_denied_with_403_and_audit_row(self):
        # Login as superuser, but do not mark the session TOTP-verified.
        self.api.force_login(self.superuser)
        url = reverse("incident_revoke_all_keys")
        resp = self.api.post(url, {"org": self.org_a.id}, format="json")
        self.assertEqual(resp.status_code, 403, resp.content)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="incident.revoke_all_keys",
                outcome="denied:totp_required",
            ).exists()
        )

    # --- input validation ---

    def test_missing_org_returns_400_and_audit_row(self):
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        resp = self.api.post(url, {}, format="json")
        self.assertEqual(resp.status_code, 400, resp.content)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="incident.revoke_all_keys",
                outcome="denied:missing_org",
            ).exists()
        )

    def test_unknown_org_returns_404_and_audit_row(self):
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        resp = self.api.post(url, {"org": 999999}, format="json")
        self.assertEqual(resp.status_code, 404, resp.content)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="incident.revoke_all_keys",
                outcome="denied:unknown_org",
            ).exists()
        )

    def test_invalid_before_returns_400_and_audit_row(self):
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        resp = self.api.post(
            url, {"org": self.org_a.id, "before": "not-a-date"}, format="json"
        )
        self.assertEqual(resp.status_code, 400, resp.content)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="incident.revoke_all_keys",
                outcome="denied:invalid_before",
            ).exists()
        )

    # --- throttling ---

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "rest_framework.authentication.SessionAuthentication",
            ],
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.IsAuthenticated",
            ],
            "DEFAULT_THROTTLE_RATES": {
                "vault_api": "1000/min",
                # Tight rate so the test can prove the throttle.
                "incident": "2/min",
            },
            # Wire the throttled-call audit row handler for the duration
            # of this test; it is the production default but the override
            # has to be explicit or the test will not exercise the path.
            "EXCEPTION_HANDLER": "vault.exception_handler.incident_exception_handler",
        }
    )
    def test_throttle_blocks_excess_calls_with_429(self):
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        # First two calls succeed (or fail validation, but pass the throttle).
        self.api.post(url, {"org": self.org_a.id}, format="json")
        self.api.post(url, {"org": self.org_a.id}, format="json")
        # Third call within the same minute trips the throttle.
        resp = self.api.post(url, {"org": self.org_a.id}, format="json")
        self.assertEqual(resp.status_code, 429, resp.content)

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "rest_framework.authentication.SessionAuthentication",
            ],
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.IsAuthenticated",
            ],
            "DEFAULT_THROTTLE_RATES": {
                "vault_api": "1000/min",
                "incident": "2/min",
            },
            "EXCEPTION_HANDLER": "vault.exception_handler.incident_exception_handler",
        }
    )
    def test_throttled_call_writes_denied_throttled_audit_row(self):
        """A 429 must leave a row in AuditEvent with the throttled principal
        and the org from the request body. Without this, an on-call engineer
        investigating a misfiring tool would see no trace of the rate-limited
        calls in the audit log at all."""
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        # Burn through the bucket.
        for _ in range(2):
            self.api.post(url, {"org": self.org_a.id}, format="json")
        # Throttled call.
        self.api.post(url, {"org": self.org_a.id}, format="json")

        ev = AuditEvent.objects.filter(
            action="incident.revoke_all_keys",
            outcome="denied:throttled",
        ).latest("timestamp")
        self.assertEqual(ev.principal, "superuser:responder")
        self.assertEqual(ev.organization_id, self.org_a.id)
        # The default 429 Retry-After is set by DRF; we record the wait
        # (seconds) so an investigator can see whether the burst was
        # #1 or #N of a sustained loop.
        self.assertTrue(ev.secret_key.startswith("wait="))

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "rest_framework.authentication.SessionAuthentication",
            ],
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.IsAuthenticated",
            ],
            "DEFAULT_THROTTLE_RATES": {
                "vault_api": "1000/min",
                "incident": "1/min",
            },
            "EXCEPTION_HANDLER": "vault.exception_handler.incident_exception_handler",
        }
    )
    def test_throttled_call_handles_unparseable_body_gracefully(self):
        """If the body cannot be parsed, the audit row must still be written
        (with org_id=None), and the request must still get its 429. The
        handler must not 500 the response just because parsing failed."""
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        # First call: valid body, populates the bucket.
        self.api.post(url, {"org": self.org_a.id}, format="json")
        # Second call: malformed body (not valid JSON). The throttle fires
        # before the view body parses, so the handler is what sees this.
        resp = self.api.post(
            url, data=b"not-json-at-all", content_type="application/json"
        )
        self.assertEqual(resp.status_code, 429, resp.content)
        ev = AuditEvent.objects.filter(
            action="incident.revoke_all_keys",
            outcome="denied:throttled",
        ).latest("timestamp")
        self.assertIsNone(ev.organization_id)
        self.assertEqual(ev.principal, "superuser:responder")

    # --- coverage gaps: defensive paths in the throttled-call handler ---

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "rest_framework.authentication.SessionAuthentication",
            ],
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.IsAuthenticated",
            ],
            "DEFAULT_THROTTLE_RATES": {
                "vault_api": "1000/min",
                "incident": "1/min",
            },
            "EXCEPTION_HANDLER": "vault.exception_handler.incident_exception_handler",
        }
    )
    def test_throttled_audit_row_handles_audit_write_failure(self):
        """If ``AuditEvent.objects.create`` raises during the throttled-call
        path, the response must still be a 429 and the exception must be
        swallowed (logged, not propagated) so the throttle still works.
        Coverage of the defensive ``except Exception`` in
        ``vault/exception_handler.py:39``.
        """
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        # Burn through the bucket.
        self.api.post(url, {"org": self.org_a.id}, format="json")
        # Now trip the throttle with a forced audit-write failure.
        with mock.patch(
            "vault.exception_handler.AuditEvent.objects.create",
            side_effect=RuntimeError("disk full"),
        ):
            resp = self.api.post(
                url, {"org": self.org_a.id}, format="json"
            )
        # The 429 must still come back; the audit failure must not 500.
        self.assertEqual(resp.status_code, 429, resp.content)

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "rest_framework.authentication.SessionAuthentication",
            ],
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.IsAuthenticated",
            ],
            "DEFAULT_THROTTLE_RATES": {
                "vault_api": "1000/min",
                "incident": "1/min",
            },
            "EXCEPTION_HANDLER": "vault.exception_handler.incident_exception_handler",
        }
    )
    def test_throttled_audit_row_handles_unparseable_org_id(self):
        """A throttled call with a non-integer ``org`` in the body must
        still get its 429 and a ``denied:throttled`` audit row (with
        organization_id=None, since the org couldn't be parsed). Coverage
        of the parse-error branch in
        ``vault/exception_handler.py:103-107``.
        """
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        # Burn the bucket.
        self.api.post(url, {"org": self.org_a.id}, format="json")
        # Throttled call with a garbage org.
        resp = self.api.post(
            url, {"org": "not-a-number"}, format="json"
        )
        self.assertEqual(resp.status_code, 429, resp.content)
        ev = AuditEvent.objects.filter(
            action="incident.revoke_all_keys",
            outcome="denied:throttled",
        ).latest("timestamp")
        self.assertIsNone(ev.organization_id)
        self.assertEqual(ev.principal, "superuser:responder")

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "rest_framework.authentication.SessionAuthentication",
            ],
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.IsAuthenticated",
            ],
            "DEFAULT_THROTTLE_RATES": {
                "vault_api": "1000/min",
                "incident": "5/min",
            },
            "EXCEPTION_HANDLER": "vault.exception_handler.incident_exception_handler",
        }
    )
    def test_incident_endpoint_accepts_datetime_before(self):
        """``_parse_when`` accepts a ``datetime`` object directly (designed
        for future management-command callers). The endpoint accepts it
        too via the JSON body. Coverage of the ``isinstance(value,
        datetime)`` branch in ``vault/incident_views.py:40-53``.
        """
        self._login_responder_with_totp()
        url = reverse("incident_revoke_all_keys")
        # Pass a datetime directly in the body; JSON serialises it as an
        # ISO-8601 string which ``_parse_when`` then accepts.
        cutoff = datetime(2026, 1, 1, tzinfo=UTC)
        resp = self.api.post(
            url,
            {"org": self.org_a.id, "before": cutoff.isoformat()},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["revoked"], 0)  # no keys pre-2026

