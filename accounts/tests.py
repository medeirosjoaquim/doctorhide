from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .models import EmailVerificationToken

User = get_user_model()


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend"
)
class PasswordResetFlowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="bob",
            email="bob@example.com",
            password="Old0Pass!2024",
        )

    def test_reset_form_renders(self):
        resp = self.client.get(reverse("accounts:password_reset"))
        self.assertEqual(resp.status_code, 200)

    def test_request_sends_email_and_redirects(self):
        resp = self.client.post(
            reverse("accounts:password_reset"),
            {"email": "bob@example.com"},
            follow=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.request["PATH_INFO"], reverse("accounts:password_reset_done")
        )
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("/reset/", mail.outbox[0].body)

    def test_confirm_sets_new_password(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)

        # The GET with the token stores it in the session and redirects to a
        # "set-password" URL where the form is actually posted.
        url = reverse(
            "accounts:password_reset_confirm",
            kwargs={"uidb64": uid, "token": token},
        )
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)

        new_password = "New0Pass!2024"
        resp = self.client.post(
            resp.url,
            {"new_password1": new_password, "new_password2": new_password},
        )
        self.assertRedirects(resp, reverse("accounts:password_reset_complete"))

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend"
)
class EmailVerificationFlowTests(TestCase):
    def setUp(self):
        self.password = "sup3rSecret!pw"

    def test_signup_sends_verification_email(self):
        """Test that signup generates token and sends verification email."""
        resp = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "testuser",
                "email": "test@example.com",
                "password1": self.password,
                "password2": self.password,
                "accept_terms": "on",
            },
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("accounts:totp_enroll"))

        user = User.objects.get(username="testuser")
        self.assertEqual(user.email, "test@example.com")
        self.assertFalse(user.email_verified)

        # Check that email was sent
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertIn("verify", email.subject.lower())
        self.assertIn("test@example.com", email.to)
        self.assertIn("/verify-email/", email.body)

        # Extract token from email
        import re
        match = re.search(r'/verify-email/([^/]+)/', email.body)
        self.assertIsNotNone(match)
        token = match.group(1)

        # Check token exists in database
        verification_token = EmailVerificationToken.objects.get(user=user)
        self.assertEqual(verification_token.token, token)

    def test_verify_email_with_valid_token(self):
        """Test that valid token marks email as verified."""
        user = User.objects.create_user(
            username="bob",
            email="bob@example.com",
            password=self.password,
        )
        self.assertFalse(user.email_verified)

        token = "test-token-12345"
        EmailVerificationToken.objects.create(user=user, token=token)

        resp = self.client.get(
            reverse("accounts:verify_email", kwargs={"token": token})
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Email verified")

        user.refresh_from_db()
        self.assertTrue(user.email_verified)

        # Token should be deleted after use
        self.assertFalse(
            EmailVerificationToken.objects.filter(user=user).exists()
        )

    def test_verify_email_with_invalid_token(self):
        """Test that invalid token shows error page."""
        resp = self.client.get(
            reverse("accounts:verify_email", kwargs={"token": "nonexistent-token"})
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid verification link")

    def test_signup_rejects_duplicate_email_case_insensitive(self):
        """Test that duplicate emails are rejected (case-insensitive)."""
        User.objects.create_user(
            username="alice",
            email="test@example.com",
            password=self.password,
        )

        resp = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "bob",
                "email": "TEST@EXAMPLE.COM",
                "password1": self.password,
                "password2": self.password,
                "accept_terms": "on",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "That email is already in use.")

    def test_signup_rejects_empty_email(self):
        """Test that signup requires email."""
        resp = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "charlie",
                "email": "",
                "password1": self.password,
                "password2": self.password,
                "accept_terms": "on",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Email is required.")
        self.assertFalse(User.objects.filter(username="charlie").exists())

    def test_unverified_user_can_still_do_totp_flow(self):
        """Test that unverified email doesn't break TOTP enrollment."""
        resp = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "dave",
                "email": "dave@example.com",
                "password1": self.password,
                "password2": self.password,
                "accept_terms": "on",
            },
        )
        self.assertEqual(resp.status_code, 302)

        user = User.objects.get(username="dave")
        self.assertFalse(user.email_verified)

        # User should still be able to proceed to TOTP enrollment
        # (TOTP flow is unchanged)
        self.assertIn("totp_pending_user_id", self.client.session)
        self.assertEqual(
            self.client.session["totp_pending_user_id"], user.pk
        )


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend"
)
class TermsAcceptanceTests(TestCase):
    def setUp(self):
        self.password = "sup3rSecret!pw"

    def test_signup_requires_terms_acceptance(self):
        """Test that signup requires the terms acceptance checkbox."""
        resp = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "testuser",
                "email": "test@example.com",
                "password1": self.password,
                "password2": self.password,
                # Deliberately missing accept_terms
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "You must accept the Terms of Service and Privacy Policy.")
        self.assertFalse(User.objects.filter(username="testuser").exists())

    def test_signup_with_terms_acceptance_stores_version_and_timestamp(self):
        """Test that signup with accepted terms stores version and timestamp."""
        resp = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "testuser",
                "email": "test@example.com",
                "password1": self.password,
                "password2": self.password,
                "accept_terms": "on",
            },
        )
        self.assertEqual(resp.status_code, 302)

        user = User.objects.get(username="testuser")
        self.assertEqual(user.accepted_terms_version, "1.0")
        self.assertIsNotNone(user.accepted_at)

    def test_signup_rejects_without_terms_checkbox(self):
        """Test that signup fails if accept_terms is empty string."""
        resp = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "testuser",
                "email": "test@example.com",
                "password1": self.password,
                "password2": self.password,
                "accept_terms": "",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "You must accept the Terms of Service and Privacy Policy.")
        self.assertFalse(User.objects.filter(username="testuser").exists())
