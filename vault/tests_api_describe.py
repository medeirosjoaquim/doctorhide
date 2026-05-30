from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from . import crypto
from .models import Project, ProjectAPIKey, Secret

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


class SecretDescribeAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="describer", password="pw")
        self.salt = crypto.generate_salt()
        self.derived = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="describe-proj",
            salt=self.salt,
            verifier=crypto.make_verifier(self.derived),
        )
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def _url(self, key):
        return reverse("api_secret_describe", args=[key])

    def test_describe_returns_metadata_without_ciphertext(self):
        Secret.objects.create(
            project=self.project,
            key="gmail.com",
            ciphertext=crypto.encrypt(self.derived, "super-secret-value"),
        )
        resp = self.client.get(self._url("gmail.com"))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["key"], "gmail.com")
        self.assertIn("created_at", data)
        self.assertIn("updated_at", data)
        self.assertIsNone(data["deleted_at"])
        self.assertNotIn("ciphertext", data)

    def test_describe_includes_deleted_at_for_soft_deleted(self):
        secret = Secret.objects.create(
            project=self.project,
            key="old",
            ciphertext=crypto.encrypt(self.derived, "v"),
        )
        secret.soft_delete()
        resp = self.client.get(self._url("old"))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["key"], "old")
        self.assertIsNotNone(data["deleted_at"])

    def test_describe_missing_key_returns_404(self):
        resp = self.client.get(self._url("nope"))
        self.assertEqual(resp.status_code, 404)

    def test_describe_requires_auth(self):
        Secret.objects.create(
            project=self.project,
            key="a",
            ciphertext=crypto.encrypt(self.derived, "v"),
        )
        anon = APIClient()
        resp = anon.get(self._url("a"))
        self.assertIn(resp.status_code, (401, 403))

    def test_describe_scoped_to_project(self):
        other_user = User.objects.create_user(username="other", password="pw")
        other_project = Project.objects.create(
            owner=other_user,
            public_id=Project.new_public_id(),
            name="other-proj",
            salt=self.salt,
            verifier=crypto.make_verifier(self.derived),
        )
        Secret.objects.create(
            project=other_project,
            key="theirs",
            ciphertext=crypto.encrypt(self.derived, "v"),
        )
        resp = self.client.get(self._url("theirs"))
        self.assertEqual(resp.status_code, 404)
