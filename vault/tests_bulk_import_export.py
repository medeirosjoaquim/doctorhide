
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


class BulkExportAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)

        # Create test secrets
        self.secret1 = Secret.objects.create(
            project=self.project,
            key="db.password",
            ciphertext=crypto.encrypt(self.key, "secret123"),
            payload_type=Secret.PAYLOAD_STRING,
            tags=["prod", "database"],
        )
        self.secret2 = Secret.objects.create(
            project=self.project,
            key="api.key",
            ciphertext=crypto.encrypt(self.key, "key456"),
            payload_type=Secret.PAYLOAD_STRING,
            tags=["prod"],
        )
        self.secret3_deleted = Secret.objects.create(
            project=self.project,
            key="old.secret",
            ciphertext=crypto.encrypt(self.key, "oldvalue"),
        )
        self.secret3_deleted.soft_delete()

        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        # Using direct paths instead of reverse() due to URL resolution issues in test runner
        self.export_url = "/api/secrets/export"
        self.import_url = "/api/secrets/import"

    def test_export_json_format(self):
        """Export secrets as JSON with metadata."""
        res = self.client.get(self.export_url, {"format": "json"})
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Check metadata
        self.assertEqual(data["project_id"], self.project.public_id)
        self.assertEqual(data["kdf"], "pbkdf2-sha256")
        self.assertEqual(data["salt"], self.project.salt)
        self.assertEqual(data["iterations"], self.project.iterations)

        # Check secrets (excluding deleted)
        self.assertEqual(len(data["secrets"]), 2)
        secrets_by_key = {s["key"]: s for s in data["secrets"]}

        self.assertIn("db.password", secrets_by_key)
        self.assertEqual(
            secrets_by_key["db.password"]["ciphertext"], self.secret1.ciphertext
        )
        self.assertEqual(secrets_by_key["db.password"]["payload_type"], "string")
        self.assertEqual(secrets_by_key["db.password"]["tags"], ["prod", "database"])

        self.assertIn("api.key", secrets_by_key)
        self.assertEqual(secrets_by_key["api.key"]["tags"], ["prod"])

        # Deleted secret should not appear
        self.assertNotIn("old.secret", secrets_by_key)

    def test_export_env_default_format(self):
        """Default export format is JSON."""
        res = self.client.get("/api/secrets/export")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("project_id", data)
        self.assertIn("secrets", data)

    def test_export_unauthenticated(self):
        """Unauthenticated requests are rejected."""
        client = APIClient()
        res = client.get("/api/secrets/export")
        self.assertEqual(res.status_code, 401)

    def test_export_empty_project(self):
        """Exporting a project with no secrets returns empty list."""
        new_project, _ = make_project(self.user, name="empty")
        api_key, token = ProjectAPIKey.generate(new_project)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

        res = client.get("/api/secrets/export?format=json")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["secrets"], [])


class BulkImportAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        # Using direct paths instead of reverse() due to URL resolution issues in test runner
        self.export_url = "/api/secrets/export"
        self.import_url = "/api/secrets/import"

    def test_import_new_secrets(self):
        """Import new secrets into the project."""
        ciphertext1 = crypto.encrypt(self.key, "secret123")
        ciphertext2 = crypto.encrypt(self.key, "secret456")

        payload = {
            "secrets": [
                {
                    "key": "db.password",
                    "ciphertext": ciphertext1,
                    "payload_type": "string",
                    "tags": ["prod"],
                },
                {
                    "key": "api.key",
                    "ciphertext": ciphertext2,
                    "payload_type": "string",
                    "tags": ["prod", "api"],
                },
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["imported"], 2)
        self.assertEqual(data["updated"], 0)
        self.assertEqual(data["errors"], [])

        # Verify secrets were created
        self.assertEqual(
            Secret.objects.filter(project=self.project, key="db.password").count(), 1
        )
        self.assertEqual(
            Secret.objects.filter(project=self.project, key="api.key").count(), 1
        )

        # Verify secret details
        secret1 = Secret.objects.get(project=self.project, key="db.password")
        self.assertEqual(secret1.ciphertext, ciphertext1)
        self.assertEqual(secret1.payload_type, "string")
        self.assertEqual(secret1.tags, ["prod"])
        self.assertIsNone(secret1.deleted_at)

        secret2 = Secret.objects.get(project=self.project, key="api.key")
        self.assertEqual(secret2.tags, ["prod", "api"])

    def test_import_update_existing_secrets(self):
        """Import can update existing secrets."""
        # Create an existing secret
        original_ciphertext = crypto.encrypt(self.key, "old_value")
        existing_secret = Secret.objects.create(
            project=self.project,
            key="db.password",
            ciphertext=original_ciphertext,
            payload_type="string",
            tags=["old"],
        )

        # Import new version
        new_ciphertext = crypto.encrypt(self.key, "new_value")
        payload = {
            "secrets": [
                {
                    "key": "db.password",
                    "ciphertext": new_ciphertext,
                    "payload_type": "string",
                    "tags": ["prod"],
                }
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["imported"], 0)
        self.assertEqual(data["updated"], 1)
        self.assertEqual(data["errors"], [])

        # Verify the secret was updated
        existing_secret.refresh_from_db()
        self.assertEqual(existing_secret.ciphertext, new_ciphertext)
        self.assertEqual(existing_secret.tags, ["prod"])

        # Verify version history was created
        versions = existing_secret.versions.all()
        self.assertEqual(versions.count(), 1)
        self.assertEqual(versions[0].ciphertext, new_ciphertext)
        self.assertEqual(versions[0].label, "imported")

    def test_import_restore_deleted_secret(self):
        """Importing can restore a previously deleted secret."""
        original_ciphertext = crypto.encrypt(self.key, "secret123")
        secret = Secret.objects.create(
            project=self.project,
            key="db.password",
            ciphertext=original_ciphertext,
        )
        secret.soft_delete()

        # Import new version
        new_ciphertext = crypto.encrypt(self.key, "new_secret")
        payload = {
            "secrets": [
                {
                    "key": "db.password",
                    "ciphertext": new_ciphertext,
                    "payload_type": "string",
                    "tags": [],
                }
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)

        # Verify the secret was restored
        secret.refresh_from_db()
        self.assertIsNone(secret.deleted_at)
        self.assertEqual(secret.ciphertext, new_ciphertext)

    def test_import_rejects_plaintext(self):
        """Importing with plaintext is rejected."""
        payload = {
            "secrets": [
                {
                    "key": "db.password",
                    "plaintext": "secret123",
                }
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["imported"], 0)
        self.assertEqual(len(data["errors"]), 1)
        self.assertIn("Plaintext is not accepted", data["errors"][0]["error"])

    def test_import_missing_required_fields(self):
        """Import validates required fields."""
        payload = {
            "secrets": [
                {
                    "key": "db.password",
                    # Missing ciphertext
                },
                {
                    "ciphertext": "test",
                    # Missing key
                },
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["imported"], 0)
        self.assertEqual(len(data["errors"]), 2)

    def test_import_invalid_payload_type(self):
        """Import validates payload_type."""
        ciphertext = crypto.encrypt(self.key, "secret123")
        payload = {
            "secrets": [
                {
                    "key": "db.password",
                    "ciphertext": ciphertext,
                    "payload_type": "invalid",
                }
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["imported"], 0)
        self.assertEqual(len(data["errors"]), 1)
        self.assertIn("payload_type must be", data["errors"][0]["error"])

    def test_import_invalid_tags(self):
        """Import validates tags format."""
        ciphertext = crypto.encrypt(self.key, "secret123")
        payload = {
            "secrets": [
                {
                    "key": "db.password",
                    "ciphertext": ciphertext,
                    "payload_type": "string",
                    "tags": "not-a-list",
                }
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["imported"], 0)
        self.assertEqual(len(data["errors"]), 1)
        self.assertIn("tags must be", data["errors"][0]["error"])

    def test_import_partial_success(self):
        """Import returns summary even when some entries fail."""
        ciphertext1 = crypto.encrypt(self.key, "secret1")
        ciphertext2 = crypto.encrypt(self.key, "secret2")

        payload = {
            "secrets": [
                {
                    "key": "good.secret",
                    "ciphertext": ciphertext1,
                    "payload_type": "string",
                },
                {
                    "key": "",  # Invalid: empty key
                    "ciphertext": ciphertext2,
                },
                {
                    "key": "another.good",
                    "ciphertext": ciphertext2,
                    "payload_type": "string",
                },
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["imported"], 2)
        self.assertEqual(data["updated"], 0)
        self.assertEqual(len(data["errors"]), 1)
        self.assertEqual(data["errors"][0]["index"], 1)

        # Verify successful secrets were created
        self.assertEqual(
            Secret.objects.filter(project=self.project, key="good.secret").count(), 1
        )
        self.assertEqual(
            Secret.objects.filter(project=self.project, key="another.good").count(), 1
        )

    def test_import_invalid_request_body(self):
        """Import rejects invalid request format."""
        # JSON array instead of object
        res = self.client.post(self.import_url, [], format="json")
        self.assertEqual(res.status_code, 400)
        self.assertIn("must be a JSON object", res.json()["detail"])

    def test_import_missing_secrets_list(self):
        """Import requires secrets list."""
        payload = {"other_field": "value"}

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 400)
        self.assertIn("secrets must be a list", res.json()["detail"])

    def test_import_unauthenticated(self):
        """Unauthenticated imports are rejected."""
        client = APIClient()
        payload = {"secrets": []}
        res = client.post("/api/secrets/import", payload, format="json")
        self.assertEqual(res.status_code, 401)

    def test_import_creates_version_history(self):
        """Imported secrets get version history."""
        ciphertext = crypto.encrypt(self.key, "secret123")
        payload = {
            "secrets": [
                {
                    "key": "new.secret",
                    "ciphertext": ciphertext,
                    "payload_type": "string",
                }
            ]
        }

        res = self.client.post(self.import_url, payload, format="json")
        self.assertEqual(res.status_code, 200)

        secret = Secret.objects.get(project=self.project, key="new.secret")
        versions = secret.versions.all()
        self.assertEqual(versions.count(), 1)
        self.assertEqual(versions[0].ciphertext, ciphertext)
        self.assertEqual(versions[0].label, "imported")


class BulkExportImportRoundTripTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)

        # Create test secrets
        self.secret1 = Secret.objects.create(
            project=self.project,
            key="db.password",
            ciphertext=crypto.encrypt(self.key, "secret123"),
            payload_type=Secret.PAYLOAD_STRING,
            tags=["prod", "database"],
        )
        self.secret2 = Secret.objects.create(
            project=self.project,
            key="api.key",
            ciphertext=crypto.encrypt(self.key, "key456"),
            payload_type=Secret.PAYLOAD_STRING,
            tags=["prod"],
        )

        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        # Using direct paths instead of reverse() due to URL resolution issues in test runner
        self.export_url = "/api/secrets/export"
        self.import_url = "/api/secrets/import"

    def test_export_import_roundtrip(self):
        """Export and reimport preserves secrets and metadata."""
        # Export
        export_res = self.client.get(self.export_url, {"format": "json"})
        self.assertEqual(export_res.status_code, 200)
        export_data = export_res.json()

        # Create a new project to import into
        new_project, _ = make_project(self.user, name="imported")
        new_api_key, new_token = ProjectAPIKey.generate(new_project)

        # Import into new project
        new_client = APIClient()
        new_client.credentials(HTTP_AUTHORIZATION=f"Bearer {new_token}")

        import_res = new_client.post(
            self.import_url,
            {"secrets": export_data["secrets"]},
            format="json",
        )
        self.assertEqual(import_res.status_code, 200)
        import_result = import_res.json()

        self.assertEqual(import_result["imported"], 2)
        self.assertEqual(import_result["errors"], [])

        # Verify imported secrets match original
        imported_secret1 = Secret.objects.get(
            project=new_project, key="db.password"
        )
        self.assertEqual(
            imported_secret1.ciphertext, self.secret1.ciphertext
        )
        self.assertEqual(imported_secret1.tags, ["prod", "database"])

        imported_secret2 = Secret.objects.get(
            project=new_project, key="api.key"
        )
        self.assertEqual(imported_secret2.ciphertext, self.secret2.ciphertext)
        self.assertEqual(imported_secret2.tags, ["prod"])
