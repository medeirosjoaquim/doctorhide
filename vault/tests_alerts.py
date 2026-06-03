"""Tests for the in-process security alert detectors.

The detector in ``vault/alerts.py`` increments the
``vault_security_alerts_total`` Prometheus counter and writes an
``AuditEvent(action='security.alert')`` row when a per-(username,
source_ip) failure threshold is crossed. These tests pin that
contract so a future refactor cannot quietly drop the alert
emission.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase

from .alerts import track_failed_login
from .metrics import vault_security_alerts_total
from .models import AuditEvent

User = get_user_model()


def _counter_value(type_: str, severity: str) -> float:
    """Read the current value of the labelled counter, defaulting to 0
    if no samples have been recorded yet."""
    return vault_security_alerts_total.labels(
        type=type_, severity=severity
    )._value.get()


class TrackFailedLoginDetectorTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username="alice", password="correct-horse-battery"
        )

    def _request(self):
        # The detector reads REMOTE_ADDR; the test client populates it
        # from the SERVER_NAME / wsgi env, defaulting to 127.0.0.1.
        req = Client().post("/")
        return req.wsgi_request

    def test_below_threshold_emits_nothing(self):
        # 4 failures is below the default 5/15min threshold.
        for _ in range(4):
            alert = track_failed_login(self._request(), username="alice", step="password")
            self.assertIsNone(alert)
        # No alert row, no counter increment.
        self.assertEqual(
            AuditEvent.objects.filter(action="security.alert").count(), 0
        )

    def test_at_threshold_emits_alert_and_audit_row(self):
        threshold = 5
        for _ in range(threshold):
            alert = track_failed_login(self._request(), username="alice", step="password")
        # The 5th call returns the alert type; calls 1-4 returned None.
        self.assertEqual(alert, "failed_login:password")

        ev = AuditEvent.objects.get(action="security.alert")
        self.assertEqual(ev.outcome, "failed_login:password")
        # The audit row carries the operator's username + source IP, so
        # the on-call engineer can start the investigation from the
        # audit log alone.
        self.assertIn("alice", ev.secret_key)
        self.assertIn("count=5", ev.secret_key)

    def test_above_threshold_does_not_emit_again(self):
        # The detector emits ONCE per (username, ip, step) per window.
        # Subsequent failures within the same window must not produce
        # additional alerts; otherwise an attacker would inflate the
        # counter and the alert would re-page every 30s.
        for _ in range(7):
            track_failed_login(self._request(), username="alice", step="password")
        # Only the 5th call returned an alert_type; calls 6, 7 returned None.
        rows = AuditEvent.objects.filter(action="security.alert")
        self.assertEqual(rows.count(), 1)

    def test_distinct_username_pairs_are_independent(self):
        # Two different (username, ip) pairs must have independent
        # counters; a brute-force against user A must not be
        # attributed to user B (and vice versa).
        req_a = self._request()
        # Build a synthetic second request with a different REMOTE_ADDR.
        req_b = self._request()
        req_b.META["REMOTE_ADDR"] = "203.0.113.7"
        for _ in range(5):
            track_failed_login(req_a, username="alice", step="password")
        # Pair (alice, 127.0.0.1) has just crossed the threshold. Pair
        # (alice, 203.0.113.7) has not — even though both are attempts
        # on the same username.
        for _ in range(4):
            track_failed_login(req_b, username="alice", step="password")
        self.assertEqual(
            AuditEvent.objects.filter(action="security.alert").count(),
            1,
        )
        # The 5th call on req_b should also emit, separately.
        alert = track_failed_login(req_b, username="alice", step="password")
        self.assertEqual(alert, "failed_login:password")
        self.assertEqual(
            AuditEvent.objects.filter(action="security.alert").count(),
            2,
        )

    def test_step_distinction_password_vs_totp(self):
        # Password failures and TOTP failures are tracked as separate
        # counters. A user who fat-fingers their password 5 times then
        # 5 correct TOTPs must NOT trip the TOTP alert; the detector
        # counts the two steps independently.
        for _ in range(5):
            track_failed_login(self._request(), username="alice", step="password")
        # Password threshold crossed. TOTP is still at 0.
        for _ in range(4):
            alert = track_failed_login(self._request(), username="alice", step="totp")
            self.assertIsNone(alert)
        # Only the password alert was emitted; totp is still under
        # its own threshold.
        self.assertEqual(
            AuditEvent.objects.filter(outcome="failed_login:password").count(),
            1,
        )
        self.assertEqual(
            AuditEvent.objects.filter(outcome="failed_login:totp").count(),
            0,
        )

    def test_alert_counted_in_prometheus_counter(self):
        # Drive the counter directly through the detector to verify
        # the metric and the audit row are emitted together.
        before = _counter_value("failed_login:password", "high")
        for _ in range(5):
            track_failed_login(self._request(), username="alice", step="password")
        after = _counter_value("failed_login:password", "high")
        self.assertEqual(after - before, 1.0)
