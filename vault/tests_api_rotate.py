from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APITestCase

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
    )
    project.default_environment.salt = salt
    project.default_environment.verifier = crypto.make_verifier(key)
    project.default_environment.save(update_fields=["salt", "verifier"])
    return project, key


class SecretRotateTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_rotate_existing_secret(self):
        """Rotating a secret should update ciphertext and create a new version."""
        ct1 = crypto.encrypt(self.key, "abc123")
        ct2 = crypto.encrypt(self.key, "def456")

        # Create secret with ct1
        res1 = self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )
        self.assertEqual(res1.status_code, 201)

        secret = Secret.objects.get(key="gmail.com")
        self.assertEqual(secret.ciphertext, ct1)
        self.assertEqual(secret.versions.count(), 1)

        # Rotate to ct2
        res2 = self.client.post(
            "/api/secrets/gmail.com/rotate",
            {"ciphertext": ct2},
            format="json",
        )
        self.assertEqual(res2.status_code, 200)
        body = res2.json()
        self.assertEqual(body["key"], "gmail.com")
        self.assertEqual(body["ciphertext"], ct2)

        # Verify secret updated and new version created
        secret.refresh_from_db()
        self.assertEqual(secret.ciphertext, ct2)
        self.assertEqual(secret.versions.count(), 2)

        versions = list(secret.versions.order_by("created_at"))
        self.assertEqual(versions[0].ciphertext, ct1)
        self.assertEqual(versions[1].ciphertext, ct2)
        self.assertEqual(versions[1].label, "rotated")

    def test_rotate_nonexistent_secret_404(self):
        """Rotating a nonexistent secret should return 404."""
        ct = crypto.encrypt(self.key, "abc123")
        res = self.client.post(
            "/api/secrets/nope.com/rotate",
            {"ciphertext": ct},
            format="json",
        )
        self.assertEqual(res.status_code, 404)
        body = res.json()
        self.assertEqual(body["detail"], "Not found.")

    def test_rotate_missing_ciphertext(self):
        """Rotating without ciphertext should return 400."""
        ct1 = crypto.encrypt(self.key, "abc123")
        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )

        res = self.client.post(
            "/api/secrets/gmail.com/rotate",
            {},
            format="json",
        )
        self.assertEqual(res.status_code, 400)
        body = res.json()
        self.assertEqual(body["detail"], "ciphertext is required.")

    def test_rotate_rejects_plaintext(self):
        """Rotating with plaintext should return 400 (zero-knowledge preserved)."""
        ct = crypto.encrypt(self.key, "abc123")
        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct},
            format="json",
        )

        res = self.client.post(
            "/api/secrets/gmail.com/rotate",
            {"plaintext": "secret-value"},
            format="json",
        )
        self.assertEqual(res.status_code, 400)
        body = res.json()
        self.assertIn("Plaintext is not accepted", body["detail"])

    def test_rotate_deleted_secret_404(self):
        """Rotating a soft-deleted secret should return 404."""
        ct = crypto.encrypt(self.key, "abc123")
        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct},
            format="json",
        )
        self.client.delete("/api/secrets/gmail.com")

        res = self.client.post(
            "/api/secrets/gmail.com/rotate",
            {"ciphertext": crypto.encrypt(self.key, "new")},
            format="json",
        )
        self.assertEqual(res.status_code, 404)

    def test_rotate_multiple_times(self):
        """Rotating a secret multiple times should create multiple versions."""
        cts = [
            crypto.encrypt(self.key, "v1"),
            crypto.encrypt(self.key, "v2"),
            crypto.encrypt(self.key, "v3"),
        ]

        # Create
        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": cts[0]},
            format="json",
        )

        # Rotate twice
        self.client.post(
            "/api/secrets/gmail.com/rotate",
            {"ciphertext": cts[1]},
            format="json",
        )
        self.client.post(
            "/api/secrets/gmail.com/rotate",
            {"ciphertext": cts[2]},
            format="json",
        )

        secret = Secret.objects.get(key="gmail.com")
        self.assertEqual(secret.ciphertext, cts[2])
        self.assertEqual(secret.versions.count(), 3)

        versions = list(secret.versions.order_by("created_at"))
        self.assertEqual(versions[0].ciphertext, cts[0])
        self.assertEqual(versions[0].label, "")
        self.assertEqual(versions[1].ciphertext, cts[1])
        self.assertEqual(versions[1].label, "rotated")
        self.assertEqual(versions[2].ciphertext, cts[2])
        self.assertEqual(versions[2].label, "rotated")

    def test_rotate_returns_project_metadata(self):
        """Rotate response should include project metadata."""
        ct1 = crypto.encrypt(self.key, "abc123")
        ct2 = crypto.encrypt(self.key, "def456")

        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )

        res = self.client.post(
            "/api/secrets/gmail.com/rotate",
            {"ciphertext": ct2},
            format="json",
        )
        body = res.json()
        self.assertEqual(body["project_id"], self.project.public_id)
        self.assertEqual(body["kdf"], "pbkdf2-sha256")
        self.assertEqual(body["salt"], self.project.salt)
        self.assertEqual(body["iterations"], self.project.iterations)

    def test_rotate_requires_authentication(self):
        """Rotate without API key should return 401."""
        client = APIClient()
        ct = crypto.encrypt(self.key, "abc123")
        res = client.post(
            "/api/secrets/gmail.com/rotate",
            {"ciphertext": ct},
            format="json",
        )
        self.assertEqual(res.status_code, 401)

    def test_rotate_audits_success(self):
        """Successful rotate should audit the action."""
        from .models import AuditEvent

        ct1 = crypto.encrypt(self.key, "abc123")
        ct2 = crypto.encrypt(self.key, "def456")

        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )

        self.client.post(
            "/api/secrets/gmail.com/rotate",
            {"ciphertext": ct2},
            format="json",
        )

        event = AuditEvent.objects.filter(
            action="secret.rotate", secret_key="gmail.com"
        ).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "success")

    def test_rotate_audits_failure(self):
        """Failed rotate (nonexistent secret) should audit the action."""
        from .models import AuditEvent

        ct = crypto.encrypt(self.key, "abc123")
        self.client.post(
            "/api/secrets/gmail.com/rotate",
            {"ciphertext": ct},
            format="json",
        )

        event = AuditEvent.objects.filter(
            action="secret.rotate", secret_key="gmail.com"
        ).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "denied")
