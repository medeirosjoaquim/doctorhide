from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from . import crypto
from .models import Project, ProjectAPIKey, Secret

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


def make_project(owner, name="prod"):
    salt = crypto.generate_salt()
    key = crypto.derive_key(PASSPHRASE, salt)
    project = Project.objects.create(
        owner=owner,
        public_id=Project.new_public_id(),
        name=name,
        salt=salt,
        verifier=crypto.make_verifier(key),
    )
    return project, key


class SecretWriteAPITests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        _, token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + token)
        self.url = reverse("api_secret_detail", args=["gmail.com"])

    def _ct(self, value="abc123"):
        return crypto.encrypt(self.key, value)

    def test_post_requires_auth(self):
        anon = APIClient()
        res = anon.post(self.url, {"ciphertext": self._ct()}, format="json")
        self.assertEqual(res.status_code, 401)

    def test_post_creates_secret(self):
        ct = self._ct()
        res = self.client.post(self.url, {"ciphertext": ct}, format="json")
        self.assertEqual(res.status_code, 201)
        secret = Secret.objects.get(project=self.project, key="gmail.com")
        self.assertEqual(secret.ciphertext, ct)

    def test_post_rejects_plaintext(self):
        res = self.client.post(self.url, {"plaintext": "supersecret"}, format="json")
        self.assertEqual(res.status_code, 400)
        self.assertFalse(Secret.objects.filter(key="gmail.com").exists())

    def test_post_requires_ciphertext(self):
        res = self.client.post(self.url, {}, format="json")
        self.assertEqual(res.status_code, 400)

    def test_post_conflict_when_exists(self):
        Secret.objects.create(
            project=self.project, key="gmail.com", ciphertext=self._ct("old")
        )
        res = self.client.post(self.url, {"ciphertext": self._ct("new")}, format="json")
        self.assertEqual(res.status_code, 409)
        secret = Secret.objects.get(key="gmail.com")
        self.assertEqual(crypto.decrypt(self.key, secret.ciphertext), "old")

    def test_post_idempotent_replay_returns_existing(self):
        body = {"ciphertext": self._ct("v1"), "ClientRequestToken": "tok-abc"}
        first = self.client.post(self.url, body, format="json")
        self.assertEqual(first.status_code, 201)
        retry = self.client.post(self.url, body, format="json")
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(Secret.objects.filter(key="gmail.com").count(), 1)

    def test_put_creates_when_missing(self):
        ct = self._ct("created")
        res = self.client.put(self.url, {"ciphertext": ct}, format="json")
        self.assertEqual(res.status_code, 201)
        self.assertEqual(Secret.objects.get(key="gmail.com").ciphertext, ct)

    def test_put_updates_existing(self):
        Secret.objects.create(
            project=self.project, key="gmail.com", ciphertext=self._ct("old")
        )
        ct = self._ct("new")
        res = self.client.put(self.url, {"ciphertext": ct}, format="json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(Secret.objects.get(key="gmail.com").ciphertext, ct)

    def test_put_rejects_plaintext(self):
        res = self.client.put(self.url, {"plaintext": "leak"}, format="json")
        self.assertEqual(res.status_code, 400)

    def test_put_idempotent_replay_does_not_reapply(self):
        Secret.objects.create(
            project=self.project, key="gmail.com", ciphertext=self._ct("v1")
        )
        first = self.client.put(
            self.url,
            {"ciphertext": self._ct("v2"), "ClientRequestToken": "tok-1"},
            format="json",
        )
        self.assertEqual(first.status_code, 200)
        # Same token but different ciphertext: replay is a no-op, keeps v2.
        retry = self.client.put(
            self.url,
            {"ciphertext": self._ct("v3"), "ClientRequestToken": "tok-1"},
            format="json",
        )
        self.assertEqual(retry.status_code, 200)
        secret = Secret.objects.get(key="gmail.com")
        self.assertEqual(crypto.decrypt(self.key, secret.ciphertext), "v2")

    def test_post_never_stores_plaintext(self):
        res = self.client.post(self.url, {"ciphertext": self._ct("abc123")}, format="json")
        self.assertEqual(res.status_code, 201)
        self.assertNotIn("abc123", Secret.objects.get(key="gmail.com").ciphertext)

    def test_write_scoped_to_authenticated_project(self):
        self.client.post(self.url, {"ciphertext": self._ct()}, format="json")
        other, _ = make_project(self.user, name="staging")
        self.assertFalse(Secret.objects.filter(project=other, key="gmail.com").exists())
