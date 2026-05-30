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


class PayloadTypeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        _, token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

    def test_default_payload_type_is_string(self):
        secret = Secret.objects.create(
            project=self.project,
            key="gmail.com",
            ciphertext="ZW5jcnlwdGVk",
        )
        self.assertEqual(secret.payload_type, Secret.PAYLOAD_STRING)
        url = reverse("api_secret_detail", args=["gmail.com"])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["payload_type"], "string")

    def test_write_and_read_binary_payload(self):
        url = reverse("api_secret_detail", args=["cert.pem"])
        resp = self.client.post(
            url,
            {"ciphertext": "YmluYXJ5LWJsb2I=", "payload_type": "binary"},
            format="json",
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["payload_type"], "binary")
        self.assertEqual(Secret.objects.get(key="cert.pem").payload_type, "binary")

    def test_describe_surfaces_payload_type(self):
        Secret.objects.create(
            project=self.project,
            key="cert.pem",
            ciphertext="YmluYXJ5LWJsb2I=",
            payload_type=Secret.PAYLOAD_BINARY,
        )
        url = reverse("api_secret_describe", args=["cert.pem"])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["payload_type"], "binary")

    def test_batch_get_surfaces_payload_type(self):
        Secret.objects.create(
            project=self.project,
            key="cert.pem",
            ciphertext="YmluYXJ5LWJsb2I=",
            payload_type=Secret.PAYLOAD_BINARY,
        )
        url = reverse("api_secrets_batch_get")
        resp = self.client.post(url, {"keys": ["cert.pem"]}, format="json")
        self.assertEqual(resp.status_code, 200)
        entry = resp.json()["secrets"][0]
        self.assertEqual(entry["payload_type"], "binary")

    def test_invalid_payload_type_rejected(self):
        url = reverse("api_secret_detail", args=["cert.pem"])
        resp = self.client.post(
            url,
            {"ciphertext": "YmluYXJ5LWJsb2I=", "payload_type": "exe"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(Secret.objects.filter(key="cert.pem").exists())
