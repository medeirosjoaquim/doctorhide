"""Wiring tests: the login view must call ``track_failed_login`` so the
in-process detector sees a failed attempt.

The detector itself is tested in ``vault/tests_alerts.py``. These
tests pin the *call site* in ``accounts.views``: a bad password must
reach the detector, and a good password must not (otherwise a single
typo on a legitimate user would start counting toward the alert
threshold).
"""

from __future__ import annotations

from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

User = get_user_model()


class LoginViewDetectorWiringTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="alice", password="correct-horse-battery"
        )

    def test_bad_password_calls_detector_with_step_password(self):
        with mock.patch("vault.alerts.track_failed_login") as mock_detect:
            resp = self.client.post(
                reverse("accounts:login"),
                {"username": "alice", "password": "WRONG"},
            )
        self.assertEqual(resp.status_code, 200)
        mock_detect.assert_called_once()
        # Inspect the kwargs. The detector is called with the
        # keyword args ``username=...`` and ``step=...``.
        _, kwargs = mock_detect.call_args
        self.assertEqual(kwargs["username"], "alice")
        self.assertEqual(kwargs["step"], "password")

    def test_good_password_does_not_call_detector(self):
        # The password step succeeds; the user is sent on to the TOTP
        # step. The detector must not be called for successful
        # authentications, otherwise a legit user fat-fingering their
        # TOTP later would start with a non-zero password counter
        # (harmless, but it muddies the signal in the audit log).
        with mock.patch("vault.alerts.track_failed_login") as mock_detect:
            self.client.post(
                reverse("accounts:login"),
                {"username": "alice", "password": "correct-horse-battery"},
            )
        mock_detect.assert_not_called()

    def test_unknown_user_also_calls_detector(self):
        # The detector must be called even when the username does
        # not exist, so an attacker who is spraying usernames gets
        # counted the same as one spraying a known account.
        with mock.patch("vault.alerts.track_failed_login") as mock_detect:
            self.client.post(
                reverse("accounts:login"),
                {"username": "ghost", "password": "anything"},
            )
        mock_detect.assert_called_once()
        _, kwargs = mock_detect.call_args
        self.assertEqual(kwargs["username"], "ghost")
        self.assertEqual(kwargs["step"], "password")
