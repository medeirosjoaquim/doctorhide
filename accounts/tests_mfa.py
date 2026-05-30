from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django_otp.oath import totp
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

User = get_user_model()

PENDING_KEY = "totp_pending_user_id"
BACKUP_CODES_KEY = "totp_backup_codes"
PASSWORD = "sup3rSecret!pw"


def current_totp(device):
    code = totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)
    return str(code).zfill(device.digits)


def confirmed_totp(user):
    return TOTPDevice.objects.create(user=user, name="default", confirmed=True)


def set_pending(client, user):
    session = client.session
    session[PENDING_KEY] = user.pk
    session.save()


class SignupStateTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_happy_path_sets_pending_and_redirects_to_enroll(self):
        resp = self.client.post(reverse("accounts:signup"), {
            "username": "carol", "email": "carol@example.com", "password1": PASSWORD, "password2": PASSWORD,
        })
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:totp_enroll"))
        self.assertEqual(User.objects.filter(username="carol").count(), 1)
        user = User.objects.get(username="carol")
        self.assertTrue(user.check_password(PASSWORD))
        self.assertEqual(self.client.session[PENDING_KEY], user.pk)
        self.assertFalse(resp.wsgi_request.user.is_authenticated)

    def test_rejects_duplicate_username_case_insensitive(self):
        User.objects.create_user(username="dave", password=PASSWORD)
        resp = self.client.post(reverse("accounts:signup"), {
            "username": "DAVE", "email": "dave2@example.com", "password1": PASSWORD, "password2": PASSWORD,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "That username is already taken.")
        self.assertEqual(User.objects.filter(username__iexact="dave").count(), 1)

    def test_rejects_mismatched_password(self):
        resp = self.client.post(reverse("accounts:signup"), {
            "username": "erin", "email": "erin@example.com", "password1": PASSWORD, "password2": "different!pw",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Passwords don&#x27;t match.")
        self.assertFalse(User.objects.filter(username="erin").exists())

    def test_rejects_weak_password(self):
        resp = self.client.post(reverse("accounts:signup"), {
            "username": "frank", "email": "frank@example.com", "password1": "password", "password2": "password",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(User.objects.filter(username="frank").exists())

    def test_rejects_empty_username(self):
        resp = self.client.post(reverse("accounts:signup"), {
            "username": "", "email": "grace@example.com", "password1": PASSWORD, "password2": PASSWORD,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Username is required.")
        self.assertEqual(User.objects.count(), 0)

    def test_redirects_verified_user_to_vault(self):
        user = User.objects.create_user(username="grace", password=PASSWORD)
        device = confirmed_totp(user)
        set_pending(self.client, user)
        self.client.post(reverse("accounts:totp_verify"), {"token": current_totp(device)})
        resp = self.client.get(reverse("accounts:signup"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("vault:projects"))


class LoginGateTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="heidi", password=PASSWORD)

    def test_correct_password_sets_pending_but_not_verified(self):
        confirmed_totp(self.user)
        resp = self.client.post(reverse("accounts:login"), {
            "username": "heidi", "password": PASSWORD,
        })
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:totp_verify"))
        self.assertEqual(self.client.session[PENDING_KEY], self.user.pk)
        self.assertFalse(resp.wsgi_request.user.is_authenticated)
        self.assertFalse(resp.wsgi_request.user.is_verified())

    def test_password_correct_without_device_routes_to_enroll(self):
        resp = self.client.post(reverse("accounts:login"), {
            "username": "heidi", "password": PASSWORD,
        })
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:totp_enroll"))
        self.assertEqual(self.client.session[PENDING_KEY], self.user.pk)

    def test_wrong_password_fails(self):
        resp = self.client.post(reverse("accounts:login"), {
            "username": "heidi", "password": "wrong-password",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid username or password.")
        self.assertNotIn(PENDING_KEY, self.client.session)
        self.assertFalse(resp.wsgi_request.user.is_authenticated)

    def test_nonexistent_username_fails_generically(self):
        resp = self.client.post(reverse("accounts:login"), {
            "username": "nobody", "password": "whatever-pw",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid username or password.")
        self.assertNotIn(PENDING_KEY, self.client.session)

    def test_inactive_user_rejected(self):
        self.user.is_active = False
        self.user.save()
        resp = self.client.post(reverse("accounts:login"), {
            "username": "heidi", "password": PASSWORD,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid username or password.")
        self.assertNotIn(PENDING_KEY, self.client.session)


class TotpEnrollTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="ivan", password=PASSWORD)

    def test_provisions_unconfirmed_device_idempotently(self):
        set_pending(self.client, self.user)
        resp = self.client.get(reverse("accounts:totp_enroll"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "data:image/png;base64,")
        self.assertEqual(TOTPDevice.objects.filter(user=self.user).count(), 1)
        self.assertFalse(TOTPDevice.objects.get(user=self.user).confirmed)
        self.client.get(reverse("accounts:totp_enroll"))
        self.assertEqual(TOTPDevice.objects.filter(user=self.user).count(), 1)

    def test_without_pending_redirects_to_login(self):
        resp = self.client.get(reverse("accounts:totp_enroll"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:login"))
        self.assertEqual(TOTPDevice.objects.count(), 0)

    def test_with_confirmed_device_redirects_to_verify(self):
        confirmed_totp(self.user)
        set_pending(self.client, self.user)
        resp = self.client.get(reverse("accounts:totp_enroll"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:totp_verify"))

    def test_post_correct_token_confirms_and_issues_backup_codes(self):
        set_pending(self.client, self.user)
        self.client.get(reverse("accounts:totp_enroll"))
        device = TOTPDevice.objects.get(user=self.user)
        resp = self.client.post(reverse("accounts:totp_enroll"), {"token": current_totp(device)})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:backup_codes"))
        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        # is_verified() lives on the OTPMiddleware-wrapped user, which isn't
        # exposed on resp.wsgi_request.user; assert the OTP device id was
        # persisted to the session, which is what marks the session verified.
        self.assertIn("otp_device_id", self.client.session)
        self.assertNotIn(PENDING_KEY, self.client.session)
        backup = StaticDevice.objects.get(user=self.user, name="backup")
        self.assertEqual(backup.token_set.count(), 10)
        self.assertEqual(len(self.client.session[BACKUP_CODES_KEY]), 10)

    def test_post_wrong_token_leaves_unconfirmed(self):
        set_pending(self.client, self.user)
        self.client.get(reverse("accounts:totp_enroll"))
        resp = self.client.post(reverse("accounts:totp_enroll"), {"token": "000000"})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "That code didn&#x27;t match.")
        self.assertFalse(TOTPDevice.objects.get(user=self.user).confirmed)
        self.assertFalse(StaticDevice.objects.filter(user=self.user, name="backup").exists())
        self.assertFalse(resp.wsgi_request.user.is_verified())


class TotpVerifyTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="judy", password=PASSWORD)

    def test_correct_token_completes_login(self):
        device = confirmed_totp(self.user)
        set_pending(self.client, self.user)
        resp = self.client.post(reverse("accounts:totp_verify"), {"token": current_totp(device)})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("vault:projects"))
        # is_verified() lives on the OTPMiddleware-wrapped user, which isn't
        # exposed on resp.wsgi_request.user; assert the OTP device id was
        # persisted to the session, which is what marks the session verified.
        self.assertIn("otp_device_id", self.client.session)
        self.assertNotIn(PENDING_KEY, self.client.session)

    def test_wrong_token_rejected(self):
        confirmed_totp(self.user)
        set_pending(self.client, self.user)
        resp = self.client.post(reverse("accounts:totp_verify"), {"token": "000000"})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid code.")
        self.assertFalse(resp.wsgi_request.user.is_verified())

    def test_without_pending_redirects_to_login(self):
        resp = self.client.get(reverse("accounts:totp_verify"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:login"))

    def test_pending_without_confirmed_device_redirects_to_enroll(self):
        TOTPDevice.objects.create(user=self.user, name="default", confirmed=False)
        set_pending(self.client, self.user)
        resp = self.client.get(reverse("accounts:totp_verify"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:totp_enroll"))

    def test_token_replay_rejected(self):
        device = confirmed_totp(self.user)
        set_pending(self.client, self.user)
        token = current_totp(device)
        first = self.client.post(reverse("accounts:totp_verify"), {"token": token})
        self.assertEqual(first["Location"], reverse("vault:projects"))
        replay_client = Client()
        set_pending(replay_client, self.user)
        second = replay_client.post(reverse("accounts:totp_verify"), {"token": token})
        self.assertEqual(second.status_code, 200)
        self.assertContains(second, "Invalid code.")
        self.assertFalse(second.wsgi_request.user.is_verified())

    def test_secret_not_leaked_on_verify_page(self):
        device = confirmed_totp(self.user)
        set_pending(self.client, self.user)
        resp = self.client.get(reverse("accounts:totp_verify"))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(TOTPDevice.objects.filter(user=self.user, confirmed=True).exists())
        self.assertNotContains(resp, device.config_url)
        self.assertNotContains(resp, "data:image/png;base64,")


class BackupCodeTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="mike", password=PASSWORD)
        confirmed_totp(self.user)
        self.backup = StaticDevice.objects.create(user=self.user, name="backup", confirmed=True)
        self.code = StaticToken.random_token()
        self.backup.token_set.create(token=self.code)

    def test_authenticates_gate_and_is_consumed(self):
        set_pending(self.client, self.user)
        before = StaticToken.objects.filter(device=self.backup).count()
        resp = self.client.post(reverse("accounts:totp_verify"), {"token": self.code})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("vault:projects"))
        # is_verified() lives on the OTPMiddleware-wrapped user, which isn't
        # exposed on resp.wsgi_request.user; assert the OTP device id was
        # persisted to the session, which is what marks the session verified.
        self.assertIn("otp_device_id", self.client.session)
        after = StaticToken.objects.filter(device=self.backup).count()
        self.assertEqual(after, before - 1)
        self.assertFalse(StaticToken.objects.filter(device=self.backup, token=self.code).exists())

    def test_single_use_rejected_on_reuse(self):
        set_pending(self.client, self.user)
        self.client.post(reverse("accounts:totp_verify"), {"token": self.code})
        reuse_client = Client()
        set_pending(reuse_client, self.user)
        resp = reuse_client.post(reverse("accounts:totp_verify"), {"token": self.code})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid code.")
        self.assertFalse(resp.wsgi_request.user.is_verified())

    def test_unknown_code_rejected(self):
        set_pending(self.client, self.user)
        resp = self.client.post(reverse("accounts:totp_verify"), {"token": "zzzzzzzzzz"})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid code.")
        self.assertFalse(resp.wsgi_request.user.is_verified())

    def test_reenroll_rotates_backup_codes(self):
        from accounts.views import _issue_backup_codes
        old_code = self.code
        _issue_backup_codes(self.user)
        self.assertFalse(StaticToken.objects.filter(token=old_code).exists())
        new_backup = StaticDevice.objects.get(user=self.user, name="backup")
        self.assertEqual(new_backup.token_set.count(), 10)
        self.assertEqual(StaticDevice.objects.filter(user=self.user, name="backup").count(), 1)


class OtpProtectedRouteTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="nina", password=PASSWORD)
        self.device = confirmed_totp(self.user)

    def test_anonymous_denied(self):
        resp = self.client.get(reverse("vault:projects"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("accounts:login"), resp["Location"])

    def test_password_only_session_denied(self):
        login = self.client.post(reverse("accounts:login"), {
            "username": "nina", "password": PASSWORD,
        })
        self.assertEqual(login["Location"], reverse("accounts:totp_verify"))
        resp = self.client.get(reverse("vault:projects"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("accounts:login"), resp["Location"])

    def test_fully_verified_session_allowed(self):
        set_pending(self.client, self.user)
        self.client.post(reverse("accounts:totp_verify"), {"token": current_totp(self.device)})
        resp = self.client.get(reverse("vault:projects"))
        self.assertEqual(resp.status_code, 200)


class BackupCodesPageAndLogoutTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="oscar", password=PASSWORD)
        self.device = confirmed_totp(self.user)

    def _verify(self):
        set_pending(self.client, self.user)
        self.client.post(reverse("accounts:totp_verify"), {"token": current_totp(self.device)})

    def test_backup_codes_page_denies_anonymous(self):
        resp = self.client.get(reverse("accounts:backup_codes"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:login"))

    def test_download_denies_anonymous(self):
        resp = self.client.get(reverse("accounts:download_backup_codes"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:login"))

    def test_download_without_codes_redirects_to_backup_codes(self):
        self._verify()
        session = self.client.session
        session.pop(BACKUP_CODES_KEY, None)
        session.save()
        resp = self.client.get(reverse("accounts:download_backup_codes"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:backup_codes"))

    def test_download_returns_pdf_for_verified_user(self):
        self._verify()
        session = self.client.session
        session[BACKUP_CODES_KEY] = ["abc123", "def456"]
        session.save()
        resp = self.client.get(reverse("accounts:download_backup_codes"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/pdf")
        self.assertIn("attachment", resp["Content-Disposition"])

    def test_logout_clears_session_and_otp_state(self):
        self._verify()
        self.assertIn("_auth_user_id", self.client.session)
        resp = self.client.get(reverse("accounts:logout"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:login"))
        self.assertNotIn("_auth_user_id", self.client.session)
        protected = self.client.get(reverse("vault:projects"))
        self.assertEqual(protected.status_code, 302)
        self.assertIn(reverse("accounts:login"), protected["Location"])
