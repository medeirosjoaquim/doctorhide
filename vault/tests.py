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
        salt=salt,
        verifier=crypto.make_verifier(key),
    )
    return project, key


class CryptoTests(APITestCase):
    def test_round_trip(self):
        salt = crypto.generate_salt()
        key = crypto.derive_key(PASSPHRASE, salt)
        token = crypto.encrypt(key, "abc123")
        self.assertEqual(crypto.decrypt(key, token), "abc123")

    def test_wrong_passphrase_fails_verifier(self):
        salt = crypto.generate_salt()
        good = crypto.derive_key(PASSPHRASE, salt)
        verifier = crypto.make_verifier(good)
        bad = crypto.derive_key("not-it", salt)
        self.assertTrue(crypto.verify_key(good, verifier))
        self.assertFalse(crypto.verify_key(bad, verifier))


class ZeroKnowledgeTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        Secret.objects.create(
            project=self.project, key="gmail.com", ciphertext=crypto.encrypt(self.key, "abc123")
        )

    def test_passphrase_is_not_stored_anywhere(self):
        # No model field holds the passphrase, and the ciphertext isn't the plaintext.
        self.assertNotIn(PASSPHRASE, self.project.verifier)
        self.assertNotIn("abc123", Secret.objects.get(key="gmail.com").ciphertext)


class SecretsAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        Secret.objects.create(
            project=self.project, key="gmail.com", ciphertext=crypto.encrypt(self.key, "abc123")
        )
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()

    def _auth(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_unauthenticated_rejected(self):
        self.assertEqual(self.client.get("/api/secrets/gmail.com").status_code, 401)

    def test_fetch_returns_ciphertext_not_plaintext(self):
        self._auth()
        res = self.client.get("/api/secrets/gmail.com")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["key"], "gmail.com")
        self.assertNotIn("abc123", body["ciphertext"])
        self.assertEqual(body["salt"], self.project.salt)
        # A client with the passphrase can decrypt locally.
        client_key = crypto.derive_key(PASSPHRASE, body["salt"], body["iterations"])
        self.assertEqual(crypto.decrypt(client_key, body["ciphertext"]), "abc123")

    def test_list_returns_keys_without_values(self):
        self._auth()
        res = self.client.get("/api/secrets")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["keys"], ["gmail.com"])

    def test_missing_key_404(self):
        self._auth()
        self.assertEqual(self.client.get("/api/secrets/nope.com").status_code, 404)

    def test_revoked_key_rejected(self):
        self.api_key.revoke()
        self._auth()
        self.assertEqual(self.client.get("/api/secrets/gmail.com").status_code, 401)


class GeneratePasswordAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()

    def _auth(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_unauthenticated_rejected(self):
        self.assertEqual(self.client.get("/api/generate-password").status_code, 401)

    def test_default_generates_value(self):
        self._auth()
        res = self.client.get("/api/generate-password")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["length"], 24)
        self.assertEqual(len(body["value"]), 24)

    def test_value_is_not_persisted(self):
        self._auth()
        before = Secret.objects.count()
        self.client.get("/api/generate-password")
        self.assertEqual(Secret.objects.count(), before)

    def test_custom_length(self):
        self._auth()
        res = self.client.get("/api/generate-password?length=40")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()["value"]), 40)

    def test_length_out_of_range_rejected(self):
        self._auth()
        self.assertEqual(self.client.get("/api/generate-password?length=4").status_code, 400)

    def test_exclude_characters(self):
        self._auth()
        res = self.client.get("/api/generate-password?exclude=abcdef&length=60")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(any(c in "abcdef" for c in res.json()["value"]))

    def test_require_types(self):
        self._auth()
        res = self.client.get("/api/generate-password?require-types=digits&length=12")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["value"].isdigit())

    def test_unknown_require_type_rejected(self):
        self._auth()
        self.assertEqual(
            self.client.get("/api/generate-password?require-types=emoji").status_code, 400
        )
