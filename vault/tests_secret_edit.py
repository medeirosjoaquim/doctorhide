from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from organizations.models import Membership, Organization

from . import crypto
from .models import Project, Secret

User = get_user_model()


class SecretEditTests(TestCase):
    """Editing a secret reuses the upsert in secret_add (update_or_create keyed
    on project+key), so re-posting the same key updates the value in place."""

    def setUp(self):
        self.user = User.objects.create_user(username="ed", password="pw")
        self._login_otp_verified(self.user)
        self.passphrase = "test-passphrase"
        salt = crypto.generate_salt()
        self.key = crypto.derive_key(self.passphrase, salt)
        org = Organization.objects.create(name="ed-org")
        Membership.objects.create(
            organization=org, user=self.user, role=Membership.ROLE_OWNER
        )
        self.project = Project.objects.create(
            owner=self.user,
            organization=org,
            public_id=Project.new_public_id(),
            name="p",
        )
        self.project.default_environment.salt = salt
        self.project.default_environment.verifier = crypto.make_verifier(self.key)
        self.project.default_environment.save(update_fields=["salt", "verifier"])
        self.secret = Secret.objects.create(
            project=self.project,
            key="gmail.com",
            ciphertext=crypto.encrypt(self.key, "old-value"),
        )
        self._unlock(self.project, self.key)

    def _login_otp_verified(self, user):
        from django_otp.plugins.otp_totp.models import TOTPDevice

        device = TOTPDevice.objects.create(user=user, confirmed=True, name="d")
        self.client.force_login(user)
        session = self.client.session
        session["otp_device_id"] = device.persistent_id
        session.save()

    def _unlock(self, project, key):
        session = self.client.session
        keys = session.get("vault_keys", {})
        keys[project.public_id] = key.decode()
        session["vault_keys"] = keys
        session.save()

    def test_edit_updates_value_without_duplicating(self):
        resp = self.client.post(
            reverse("vault:secret_add", kwargs={"public_id": self.project.public_id}),
            {"key": "gmail.com", "value": "new-value"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(self.project.secrets.filter(key="gmail.com").count(), 1)
        self.secret.refresh_from_db()
        self.assertEqual(crypto.decrypt(self.key, self.secret.ciphertext), "new-value")

    def test_edit_form_shows_when_revealed_with_edit_flag(self):
        resp = self.client.get(
            reverse("vault:detail", kwargs={"public_id": self.project.public_id})
            + f"?reveal={self.secret.id}&edit={self.secret.id}"
        )
        self.assertEqual(resp.status_code, 200)
        # The inline edit form is prefilled with the decrypted current value.
        self.assertContains(resp, 'value="old-value"')
        self.assertContains(resp, "Save")

    def test_edit_button_present_when_revealed(self):
        resp = self.client.get(
            reverse("vault:detail", kwargs={"public_id": self.project.public_id})
            + f"?reveal={self.secret.id}"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, f"?reveal={self.secret.id}&edit={self.secret.id}")
