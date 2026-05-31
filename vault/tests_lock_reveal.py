from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from organizations.models import Membership, Organization
from . import crypto
from .models import Project, Secret

User = get_user_model()


class LockRevealTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="lk", password="pw")
        from django_otp.plugins.otp_totp.models import TOTPDevice
        device = TOTPDevice.objects.create(user=self.user, confirmed=True, name="d")
        self.client.force_login(self.user)
        s = self.client.session
        s["otp_device_id"] = device.persistent_id
        s.save()

        self.passphrase = "the-salt-value"
        salt = crypto.generate_salt()
        self.key = crypto.derive_key(self.passphrase, salt)
        org = Organization.objects.create(name="o")
        Membership.objects.create(organization=org, user=self.user, role=Membership.ROLE_OWNER)
        self.project = Project.objects.create(
            owner=self.user, organization=org, public_id=Project.new_public_id(),
            name="p", salt=salt, verifier=crypto.make_verifier(self.key),
        )
        self.secret = Secret.objects.create(
            project=self.project, key="gmail.com",
            ciphertext=crypto.encrypt(self.key, "PLAINTEXT-SECRET"),
        )

    def _detail_url(self, reveal=None):
        url = reverse("vault:detail", kwargs={"public_id": self.project.public_id})
        return url + (f"?reveal={self.secret.id}" if reveal else "")

    def test_locked_reveal_does_not_show_plaintext(self):
        # Project is locked (never unlocked). Reveal must NOT decrypt.
        resp = self.client.get(self._detail_url(reveal=True))
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "PLAINTEXT-SECRET")

    def test_unlock_then_reveal_shows_plaintext(self):
        self.client.post(
            reverse("vault:unlock", kwargs={"public_id": self.project.public_id}),
            {"passphrase": self.passphrase},
        )
        resp = self.client.get(self._detail_url(reveal=True))
        self.assertContains(resp, "PLAINTEXT-SECRET")

    def test_lock_after_unlock_then_reveal_hides_plaintext(self):
        # Unlock, confirm reveal works, then Lock, then reveal must hide it again.
        self.client.post(
            reverse("vault:unlock", kwargs={"public_id": self.project.public_id}),
            {"passphrase": self.passphrase},
        )
        self.assertContains(self.client.get(self._detail_url(reveal=True)), "PLAINTEXT-SECRET")

        self.client.post(reverse("vault:lock", kwargs={"public_id": self.project.public_id}))

        resp = self.client.get(self._detail_url(reveal=True))
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "PLAINTEXT-SECRET")
