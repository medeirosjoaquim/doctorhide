from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from . import crypto
from .models import Project, ProjectAPIKey, Secret

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


class ListSecretsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="alice", password="pw")
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="listproj",
        )
        env = self.project.default_environment
        env.salt = self.salt
        env = self.project.default_environment

        env.verifier = crypto.make_verifier(self.key)
        env.save(update_fields=["salt", "verifier"])
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def _url(self):
        return reverse("api_secrets_list")

    def _mksecrets(self, keys):
        for key in keys:
            Secret.objects.create(
                project=self.project,
                key=key,
                ciphertext=crypto.encrypt(self.key, "v"),
            )

    def test_prefix_filter(self):
        self._mksecrets(["DB_HOST", "DB_PASSWORD", "API_KEY"])
        resp = self.client.get(self._url(), {"prefix": "DB_"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["keys"], ["DB_HOST", "DB_PASSWORD"])
        self.assertEqual(resp.data["count"], 2)

    def test_limit_and_offset(self):
        self._mksecrets([f"S{i:02d}" for i in range(5)])
        resp = self.client.get(self._url(), {"limit": 2, "offset": 1})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["keys"], ["S01", "S02"])
        self.assertEqual(resp.data["count"], 5)
        self.assertEqual(resp.data["limit"], 2)
        self.assertEqual(resp.data["offset"], 1)

    def test_invalid_pagination_params_fall_back(self):
        self._mksecrets(["A", "B"])
        resp = self.client.get(self._url(), {"limit": "nope", "offset": "-3"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["keys"], ["A", "B"])
        self.assertEqual(resp.data["offset"], 0)

    def test_values_never_returned(self):
        self._mksecrets(["K1"])
        resp = self.client.get(self._url())
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("ciphertext", resp.data)
        self.assertNotIn("secrets", resp.data)
        self.assertEqual(resp.data["keys"], ["K1"])

    def test_soft_deleted_excluded(self):
        self._mksecrets(["LIVE"])
        gone = Secret.objects.create(
            project=self.project,
            key="GONE",
            ciphertext=crypto.encrypt(self.key, "v"),
        )
        gone.soft_delete()
        resp = self.client.get(self._url())
        self.assertEqual(resp.data["keys"], ["LIVE"])
        self.assertEqual(resp.data["count"], 1)
