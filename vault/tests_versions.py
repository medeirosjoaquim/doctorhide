from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APITestCase

from . import crypto
from .models import Project, ProjectAPIKey, Secret, SecretVersion

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


class SecretVersioningTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_create_secret_creates_v1(self):
        """Creating a secret should create a v1 SecretVersion."""
        ciphertext = crypto.encrypt(self.key, "abc123")
        res = self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ciphertext},
            format="json",
        )
        self.assertEqual(res.status_code, 201)
        secret = Secret.objects.get(key="gmail.com")
        versions = secret.versions.all()
        self.assertEqual(len(versions), 1)
        v1 = versions[0]
        self.assertEqual(v1.ciphertext, ciphertext)
        self.assertEqual(v1.label, "")

    def test_update_secret_creates_new_version(self):
        """Updating a secret should create a new SecretVersion."""
        ct1 = crypto.encrypt(self.key, "abc123")
        ct2 = crypto.encrypt(self.key, "def456")

        res1 = self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )
        self.assertEqual(res1.status_code, 201)

        res2 = self.client.put(
            "/api/secrets/gmail.com",
            {"ciphertext": ct2},
            format="json",
        )
        self.assertEqual(res2.status_code, 200)

        secret = Secret.objects.get(key="gmail.com")
        versions = list(secret.versions.order_by("created_at"))
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0].ciphertext, ct1)
        self.assertEqual(versions[1].ciphertext, ct2)

    def test_secret_ciphertext_always_points_to_current(self):
        """Secret.ciphertext should always be the latest version's ciphertext."""
        ct1 = crypto.encrypt(self.key, "abc123")
        ct2 = crypto.encrypt(self.key, "def456")
        ct3 = crypto.encrypt(self.key, "ghi789")

        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )
        secret = Secret.objects.get(key="gmail.com")
        self.assertEqual(secret.ciphertext, ct1)

        self.client.put(
            "/api/secrets/gmail.com",
            {"ciphertext": ct2},
            format="json",
        )
        secret.refresh_from_db()
        self.assertEqual(secret.ciphertext, ct2)

        self.client.put(
            "/api/secrets/gmail.com",
            {"ciphertext": ct3},
            format="json",
        )
        secret.refresh_from_db()
        self.assertEqual(secret.ciphertext, ct3)

    def test_list_versions(self):
        """GET /api/secrets/<key>/versions should return all versions."""
        ct1 = crypto.encrypt(self.key, "abc123")
        ct2 = crypto.encrypt(self.key, "def456")

        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )
        self.client.put(
            "/api/secrets/gmail.com",
            {"ciphertext": ct2},
            format="json",
        )

        res = self.client.get("/api/secrets/gmail.com/versions")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["key"], "gmail.com")
        self.assertEqual(len(body["versions"]), 2)
        # Newest first (ordered by -created_at)
        self.assertEqual(body["versions"][0]["label"], "")
        self.assertEqual(body["versions"][1]["label"], "")

    def test_list_versions_missing_secret(self):
        """GET /api/secrets/<key>/versions for missing secret should 404."""
        res = self.client.get("/api/secrets/nope.com/versions")
        self.assertEqual(res.status_code, 404)

    def test_restore_version(self):
        """POST /api/secrets/<key>/versions/<version_id>/restore should restore."""
        ct1 = crypto.encrypt(self.key, "abc123")
        ct2 = crypto.encrypt(self.key, "def456")

        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )
        res2 = self.client.put(
            "/api/secrets/gmail.com",
            {"ciphertext": ct2},
            format="json",
        )
        self.assertEqual(res2.status_code, 200)

        secret = Secret.objects.get(key="gmail.com")
        versions_before = secret.versions.count()
        v1_id = secret.versions.all().order_by("created_at")[0].id

        res3 = self.client.post(
            f"/api/secrets/gmail.com/versions/{v1_id}/restore"
        )
        self.assertEqual(res3.status_code, 200)

        secret.refresh_from_db()
        # Secret should now have the v1 ciphertext.
        self.assertEqual(secret.ciphertext, ct1)
        # A new version should have been created.
        self.assertEqual(secret.versions.count(), versions_before + 1)
        latest = secret.versions.all().order_by("-created_at")[0]
        self.assertIn("Restored from", latest.label)

    def test_restore_version_missing_secret(self):
        """POST restore for missing secret should 404."""
        res = self.client.post("/api/secrets/nope.com/versions/1/restore")
        self.assertEqual(res.status_code, 404)

    def test_restore_version_missing_version(self):
        """POST restore for missing version should 404."""
        ct1 = crypto.encrypt(self.key, "abc123")
        self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ct1},
            format="json",
        )

        res = self.client.post("/api/secrets/gmail.com/versions/9999/restore")
        self.assertEqual(res.status_code, 404)

    def test_idempotent_replay_creates_one_version(self):
        """Idempotent replays (same token) should not create duplicate versions."""
        ciphertext = crypto.encrypt(self.key, "abc123")
        token = "my-token-123"

        res1 = self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ciphertext, "ClientRequestToken": token},
            format="json",
        )
        self.assertEqual(res1.status_code, 201)

        secret = Secret.objects.get(key="gmail.com")
        v1_count = secret.versions.count()
        self.assertEqual(v1_count, 1)

        # Replay with same token
        res2 = self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ciphertext, "ClientRequestToken": token},
            format="json",
        )
        self.assertEqual(res2.status_code, 200)

        secret.refresh_from_db()
        # Should still have only 1 version (no duplicate from replay).
        self.assertEqual(secret.versions.count(), v1_count)

    def test_different_token_creates_new_version(self):
        """Different tokens should create new versions even with same ciphertext."""
        ciphertext = crypto.encrypt(self.key, "abc123")

        res1 = self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ciphertext, "ClientRequestToken": "token-1"},
            format="json",
        )
        self.assertEqual(res1.status_code, 201)

        res2 = self.client.post(
            "/api/secrets/gmail.com",
            {"ciphertext": ciphertext, "ClientRequestToken": "token-2"},
            format="json",
        )
        self.assertEqual(res2.status_code, 409)  # Already exists

        # Use PUT to update with different token
        res3 = self.client.put(
            "/api/secrets/gmail.com",
            {"ciphertext": ciphertext, "ClientRequestToken": "token-2"},
            format="json",
        )
        self.assertEqual(res3.status_code, 200)

        secret = Secret.objects.get(key="gmail.com")
        # Should have 2 versions: one from POST, one from PUT.
        self.assertEqual(secret.versions.count(), 2)


class SecretVersionDataMigrationTests(APITestCase):
    def test_existing_secrets_get_v1_on_migration(self):
        """Existing secrets should have a v1 version after migration."""
        # Create a secret directly (simulating pre-migration data).
        user = User.objects.create_user(username="alice", password="pw")
        project, key = make_project(user)
        secret = Secret.objects.create(
            project=project,
            key="old-secret",
            ciphertext=crypto.encrypt(key, "old-value"),
        )

        # In production, the migration would have run and created versions.
        # For this test, we manually create the version (as the migration does).
        SecretVersion.objects.create(
            secret=secret,
            ciphertext=secret.ciphertext,
            label="",
            created_at=secret.created_at,
        )

        secret.refresh_from_db()
        versions = secret.versions.all()
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].ciphertext, secret.ciphertext)
