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


class SecretsBatchGetAPITests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        _, token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + token)
        self.url = reverse("api_secrets_batch_get")

        self.db_ct = crypto.encrypt(self.key, "db-secret")
        self.api_ct = crypto.encrypt(self.key, "api-secret")
        Secret.objects.create(
            project=self.project, key="DB_PASSWORD", ciphertext=self.db_ct
        )
        Secret.objects.create(
            project=self.project, key="API_KEY", ciphertext=self.api_ct
        )
        gone = Secret.objects.create(
            project=self.project,
            key="OLD",
            ciphertext=crypto.encrypt(self.key, "old"),
        )
        gone.soft_delete()

    def test_post_requires_auth(self):
        anon = APIClient()
        res = anon.post(self.url, {"keys": ["DB_PASSWORD"]}, format="json")
        self.assertEqual(res.status_code, 401)

    def test_post_returns_ciphertext_for_multiple_keys(self):
        res = self.client.post(
            self.url, {"keys": ["DB_PASSWORD", "API_KEY"]}, format="json"
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["project_id"], self.project.public_id)
        returned = {s["key"]: s["ciphertext"] for s in body["secrets"]}
        self.assertEqual(
            returned, {"DB_PASSWORD": self.db_ct, "API_KEY": self.api_ct}
        )
        self.assertEqual(body["missing"], [])

    def test_get_with_repeated_key_params(self):
        res = self.client.get(self.url + "?key=DB_PASSWORD&key=API_KEY")
        self.assertEqual(res.status_code, 200)
        returned = {s["key"] for s in res.json()["secrets"]}
        self.assertEqual(returned, {"DB_PASSWORD", "API_KEY"})

    def test_missing_and_soft_deleted_keys_reported(self):
        res = self.client.post(
            self.url, {"keys": ["DB_PASSWORD", "OLD", "NOPE"]}, format="json"
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual([s["key"] for s in body["secrets"]], ["DB_PASSWORD"])
        self.assertEqual(set(body["missing"]), {"OLD", "NOPE"})

    def test_never_returns_plaintext(self):
        res = self.client.post(self.url, {"keys": ["DB_PASSWORD"]}, format="json")
        self.assertNotIn("db-secret", res.content.decode())

    def test_empty_keys_rejected(self):
        res = self.client.post(self.url, {"keys": []}, format="json")
        self.assertEqual(res.status_code, 400)

    def test_missing_keys_field_rejected(self):
        res = self.client.post(self.url, {}, format="json")
        self.assertEqual(res.status_code, 400)

    def test_scoped_to_authenticated_project(self):
        other_user = User.objects.create_user(username="bob", password="pw")
        other, other_key = make_project(other_user, name="staging")
        Secret.objects.create(
            project=other,
            key="DB_PASSWORD",
            ciphertext=crypto.encrypt(other_key, "leak"),
        )
        res = self.client.post(self.url, {"keys": ["DB_PASSWORD"]}, format="json")
        returned = {s["key"]: s["ciphertext"] for s in res.json()["secrets"]}
        self.assertEqual(returned, {"DB_PASSWORD": self.db_ct})
