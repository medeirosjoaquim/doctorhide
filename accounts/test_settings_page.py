from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django_otp.oath import totp
from django_otp.plugins.otp_totp.models import TOTPDevice

User = get_user_model()

PENDING_KEY = "totp_pending_user_id"
PASSWORD = "sup3rSecret!pw"


def current_totp(device):
    code = totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)
    return str(code).zfill(device.digits)


class AccountSettingsTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="alice", password=PASSWORD)
        self.device = TOTPDevice.objects.create(
            user=self.user, name="default", confirmed=True
        )

    def _verify(self):
        # Drive the real login + TOTP flow so the session is OTP-verified.
        session = self.client.session
        session[PENDING_KEY] = self.user.pk
        session.save()
        self.client.post(
            reverse("accounts:totp_verify"), {"token": current_totp(self.device)}
        )

    def test_requires_otp_verified_session(self):
        # Password-only (not verified) sessions are bounced to login.
        resp = self.client.get(reverse("accounts:settings"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("accounts:login"), resp["Location"])

    def test_renders_account_info_when_verified(self):
        self._verify()
        resp = self.client.get(reverse("accounts:settings"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "alice")
        self.assertContains(resp, "Change password")

    def test_change_password_success(self):
        self._verify()
        new_pw = "an0therSecret!pw"
        resp = self.client.post(
            reverse("accounts:settings"),
            {
                "old_password": PASSWORD,
                "new_password1": new_pw,
                "new_password2": new_pw,
            },
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:settings"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_pw))

    def test_change_password_rejects_weak(self):
        self._verify()
        resp = self.client.post(
            reverse("accounts:settings"),
            {
                "old_password": PASSWORD,
                "new_password1": "123",
                "new_password2": "123",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(PASSWORD))
