from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from . import crypto
from .models import Project, ProjectAPIKey, Secret

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


class SecretTagsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="alice", password="pw")
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="tagproj",
            salt=self.salt,
            verifier=crypto.make_verifier(self.key),
        )
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def _list_url(self):
        return reverse("api_secrets_list")

    def _detail_url(self, key):
        return reverse("api_secret_detail", args=[key])

    def _mksecret(self, key, tags):
        Secret.objects.create(
            project=self.project,
            key=key,
            ciphertext=crypto.encrypt(self.key, "v"),
            tags=tags,
        )

    def test_tag_filter(self):
        self._mksecret("DB_HOST", ["db", "prod"])
        self._mksecret("API_KEY", ["api"])
        self._mksecret("DB_PASSWORD", ["db"])
        resp = self.client.get(self._list_url(), {"tag": "db"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["keys"], ["DB_HOST", "DB_PASSWORD"])
        self.assertEqual(resp.data["count"], 2)

    def test_tag_filter_no_match(self):
        self._mksecret("API_KEY", ["api"])
        resp = self.client.get(self._list_url(), {"tag": "missing"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["keys"], [])
        self.assertEqual(resp.data["count"], 0)

    def test_create_persists_tags(self):
        resp = self.client.post(
            self._detail_url("NEW"),
            {"ciphertext": crypto.encrypt(self.key, "v"), "tags": ["a", "b"]},
            format="json",
        )
        self.assertEqual(resp.status_code, 201)
        secret = Secret.objects.get(project=self.project, key="NEW")
        self.assertEqual(secret.tags, ["a", "b"])

    def test_create_without_tags_defaults_empty(self):
        resp = self.client.post(
            self._detail_url("NOTAG"),
            {"ciphertext": crypto.encrypt(self.key, "v")},
            format="json",
        )
        self.assertEqual(resp.status_code, 201)
        secret = Secret.objects.get(project=self.project, key="NOTAG")
        self.assertEqual(secret.tags, [])

    def test_invalid_tags_rejected(self):
        resp = self.client.post(
            self._detail_url("BAD"),
            {"ciphertext": crypto.encrypt(self.key, "v"), "tags": "notalist"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(Secret.objects.filter(key="BAD").exists())
