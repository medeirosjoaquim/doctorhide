from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from . import crypto
from .models import AuditEvent, Project, ProjectAPIKey, Secret

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


class AuditEventTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="alice", password="pw")
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="auditproj",
        )
        env = self.project.default_environment
        env.salt = self.salt
        env = self.project.default_environment

        env.verifier = crypto.make_verifier(self.key)
        env.save(update_fields=["salt", "verifier"])
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def _mksecret(self, key="DB_PASSWORD"):
        return Secret.objects.create(
            project=self.project,
            key=key,
            ciphertext=crypto.encrypt(self.key, "v"),
        )

    def test_read_writes_success_event_and_key_auth(self):
        self._mksecret()
        url = reverse("api_secret_detail", args=["DB_PASSWORD"])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

        read = AuditEvent.objects.get(action="secret.read")
        self.assertEqual(read.outcome, "success")
        self.assertEqual(read.project, self.project)
        self.assertEqual(read.secret_key, "DB_PASSWORD")
        self.assertEqual(read.principal, self.api_key.prefix)

        self.assertTrue(
            AuditEvent.objects.filter(action="key.auth", outcome="success").exists()
        )

    def test_list_writes_event(self):
        url = reverse("api_secrets_list")
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="secret.list", outcome="success", project=self.project
            ).exists()
        )

    def test_create_and_delete_write_mutation_events(self):
        url = reverse("api_secret_detail", args=["NEWKEY"])
        ct = crypto.encrypt(self.key, "v")
        resp = self.client.post(url, {"ciphertext": ct}, format="json")
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="secret.create", outcome="success", secret_key="NEWKEY"
            ).exists()
        )

        resp = self.client.delete(url)
        self.assertEqual(resp.status_code, 204)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="secret.delete", outcome="success", secret_key="NEWKEY"
            ).exists()
        )

    def test_invalid_key_writes_denied_event(self):
        self.client.credentials(HTTP_AUTHORIZATION="Bearer dhk_bogus_token")
        url = reverse("api_secrets_list")
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 401)
        self.assertTrue(
            AuditEvent.objects.filter(action="key.auth", outcome="denied").exists()
        )

    def test_missing_secret_writes_denied_event(self):
        url = reverse("api_secret_detail", args=["NOPE"])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 404)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="secret.read", outcome="denied", secret_key="NOPE"
            ).exists()
        )

    def test_source_ip_recorded(self):
        url = reverse("api_secrets_list")
        self.client.get(url, HTTP_X_FORWARDED_FOR="203.0.113.7, 10.0.0.1")
        event = AuditEvent.objects.filter(action="secret.list").latest("timestamp")
        self.assertEqual(event.source_ip, "203.0.113.7")
