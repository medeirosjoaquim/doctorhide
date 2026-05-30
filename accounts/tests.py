from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

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
