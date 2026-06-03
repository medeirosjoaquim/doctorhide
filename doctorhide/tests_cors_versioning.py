from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from vault import crypto
from vault.models import Project, ProjectAPIKey, Secret

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


class APIVersioningTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="alice", password="pw")
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="versiontest",
        )
        self.project.default_environment.salt = self.salt
        self.project.default_environment.verifier = crypto.make_verifier(self.key)
        self.project.default_environment.save(update_fields=["salt", "verifier"])
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        Secret.objects.create(
            project=self.project,
            key="TEST_SECRET",
            ciphertext=crypto.encrypt(self.key, "test_value"),
        )

    def test_api_endpoint_works_at_legacy_path(self):
        resp = self.client.get("/api/secrets")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("keys", resp.data)

    def test_api_endpoint_works_at_v1_path(self):
        resp = self.client.get("/v1/api/secrets")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("keys", resp.data)

    def test_both_paths_return_same_data(self):
        resp_legacy = self.client.get("/api/secrets")
        resp_v1 = self.client.get("/v1/api/secrets")
        self.assertEqual(resp_legacy.status_code, 200)
        self.assertEqual(resp_v1.status_code, 200)
        self.assertEqual(resp_legacy.data, resp_v1.data)

    def test_v1_list_secrets(self):
        resp = self.client.get("/v1/api/secrets")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["keys"], ["TEST_SECRET"])

    def test_v1_describe_secret(self):
        resp = self.client.get("/v1/api/secrets/TEST_SECRET/describe")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["key"], "TEST_SECRET")

    def test_v1_batch_get(self):
        resp = self.client.post(
            "/v1/api/secrets/batch",
            {"keys": ["TEST_SECRET"]},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("secrets", resp.data)
        secret_keys = [s["key"] for s in resp.data["secrets"]]
        self.assertIn("TEST_SECRET", secret_keys)


@override_settings(CORS_ALLOWED_ORIGINS=["https://app.example.com"])
class CORSPreflight(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="bob", password="pw")
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="corstest",
        )
        self.project.default_environment.salt = self.salt
        self.project.default_environment.verifier = crypto.make_verifier(self.key)
        self.project.default_environment.save(update_fields=["salt", "verifier"])
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_cors_preflight_request(self):
        resp = self.client.options(
            "/api/secrets",
            HTTP_ORIGIN="https://app.example.com",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="GET",
        )
        self.assertEqual(resp.status_code, 200)

    def test_cors_preflight_request_v1(self):
        resp = self.client.options(
            "/v1/api/secrets",
            HTTP_ORIGIN="https://app.example.com",
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="GET",
        )
        self.assertEqual(resp.status_code, 200)

    def test_cors_headers_present_in_response(self):
        resp = self.client.get(
            "/api/secrets",
            HTTP_ORIGIN="https://app.example.com",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Access-Control-Allow-Origin", resp)
        self.assertEqual(
            resp["Access-Control-Allow-Origin"], "https://app.example.com"
        )

    def test_cors_headers_present_in_v1_response(self):
        resp = self.client.get(
            "/v1/api/secrets",
            HTTP_ORIGIN="https://app.example.com",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Access-Control-Allow-Origin", resp)
        self.assertEqual(
            resp["Access-Control-Allow-Origin"], "https://app.example.com"
        )


class CORSOriginTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username="charlie", password="pw")
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="corsorigintest",
        )
        self.project.default_environment.salt = self.salt
        self.project.default_environment.verifier = crypto.make_verifier(self.key)
        self.project.default_environment.save(update_fields=["salt", "verifier"])
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    @override_settings(CORS_ALLOWED_ORIGINS=[])
    def test_cors_disabled_by_default(self):
        resp = self.client.get(
            "/api/secrets",
            HTTP_ORIGIN="https://example.com",
        )
        self.assertEqual(resp.status_code, 200)

    @override_settings(
        CORS_ALLOWED_ORIGINS=["https://app.example.com", "https://www.example.com"]
    )
    def test_cors_multiple_origins(self):
        resp = self.client.get(
            "/api/secrets",
            HTTP_ORIGIN="https://www.example.com",
        )
        self.assertEqual(resp.status_code, 200)
