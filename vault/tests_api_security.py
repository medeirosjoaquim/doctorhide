from datetime import timedelta

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

from . import crypto
from .models import Project, ProjectAPIKey, Secret

User = get_user_model()

PASSPHRASE = "correct-horse-battery"
PLAINTEXT = "super-secret-value"


def make_project(owner, name="prod"):
    salt = crypto.generate_salt()
    key = crypto.derive_key(PASSPHRASE, salt)
    project = Project.objects.create(
        owner=owner,
        public_id=Project.new_public_id(),
        name=name,
    )
    env = project.default_environment
    env.salt = salt
    env.verifier = crypto.make_verifier(key)
    env.save(update_fields=["salt", "verifier"])
    return project, key


def add_secret(project, project_key, key, plaintext=PLAINTEXT):
    return Secret.objects.create(
        project=project, key=key, ciphertext=crypto.encrypt(project_key, plaintext)
    )


def bearer(token):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


LIST_URL = "/api/secrets"


def detail_url(key):
    return f"/api/secrets/{key}"


class AuthHeaderShapeTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        add_secret(self.project, self.key, "gmail.com")
        self.api_key, self.token = ProjectAPIKey.generate(self.project)

    def test_no_authorization_header_rejected_on_list(self):
        self.assertEqual(self.client.get(LIST_URL).status_code, 401)

    def test_no_authorization_header_rejected_on_detail(self):
        self.assertEqual(self.client.get(detail_url("gmail.com")).status_code, 401)

    def test_non_bearer_token_scheme_rejected(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {self.token}")
        self.assertEqual(client.get(LIST_URL).status_code, 401)

    def test_non_bearer_basic_scheme_rejected(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Basic {self.token}")
        self.assertEqual(client.get(LIST_URL).status_code, 401)

    def test_bearer_without_credentials_is_malformed(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Bearer")
        self.assertEqual(client.get(LIST_URL).status_code, 401)

    def test_bearer_with_extra_parts_is_malformed(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token} extra")
        self.assertEqual(client.get(LIST_URL).status_code, 401)


class TokenPrefixTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        self.api_key, self.token = ProjectAPIKey.generate(self.project)

    def test_wrong_key_prefix_rejected(self):
        bad = self.token.replace("dhk_", "xxx_", 1)
        self.assertEqual(bearer(bad).get(LIST_URL).status_code, 401)

    def test_split_token_returns_none_for_wrong_prefix(self):
        self.assertEqual(ProjectAPIKey.split_token("dh_live_abc"), (None, None))

    def test_malformed_dhk_token_without_secret_segment_rejected(self):
        self.assertEqual(bearer("dhk_onlyprefix").get(LIST_URL).status_code, 401)

    def test_split_token_returns_none_without_secret_segment(self):
        self.assertEqual(ProjectAPIKey.split_token("dhk_onlyprefix"), (None, None))

    def test_well_formed_token_unknown_prefix_rejected(self):
        prefix, _ = ProjectAPIKey.split_token(self.token)
        unknown = f"{prefix}ZZZZ_{'a' * 32}"
        self.assertEqual(bearer(unknown).get(LIST_URL).status_code, 401)

    def test_correct_prefix_wrong_secret_rejected(self):
        prefix, _ = ProjectAPIKey.split_token(self.token)
        tampered = f"{prefix}_{'0' * 32}"
        self.assertEqual(bearer(tampered).get(LIST_URL).status_code, 401)


class KeyLifecycleTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        add_secret(self.project, self.key, "gmail.com")
        self.api_key, self.token = ProjectAPIKey.generate(self.project)

    def test_expired_key_rejected_on_list(self):
        self.api_key.expires_at = timezone.now() - timedelta(seconds=1)
        self.api_key.save(update_fields=["expires_at"])
        self.assertEqual(bearer(self.token).get(LIST_URL).status_code, 401)

    def test_expired_key_rejected_on_detail(self):
        self.api_key.expires_at = timezone.now() - timedelta(seconds=1)
        self.api_key.save(update_fields=["expires_at"])
        self.assertEqual(bearer(self.token).get(detail_url("gmail.com")).status_code, 401)

    def test_future_expiry_key_still_active(self):
        self.api_key.expires_at = timezone.now() + timedelta(days=1)
        self.api_key.save(update_fields=["expires_at"])
        self.assertEqual(bearer(self.token).get(LIST_URL).status_code, 200)

    def test_revoked_key_rejected_on_list(self):
        self.api_key.revoke()
        self.assertEqual(bearer(self.token).get(LIST_URL).status_code, 401)

    def test_revoked_key_rejected_on_detail(self):
        self.api_key.revoke()
        self.assertEqual(bearer(self.token).get(detail_url("gmail.com")).status_code, 401)

    def test_last_used_at_stamped_on_success(self):
        self.assertIsNone(self.api_key.last_used_at)
        self.assertEqual(bearer(self.token).get(LIST_URL).status_code, 200)
        self.api_key.refresh_from_db()
        self.assertIsNotNone(self.api_key.last_used_at)


class ZeroKnowledgeResponseTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        add_secret(self.project, self.key, "gmail.com")
        self.api_key, self.token = ProjectAPIKey.generate(self.project)

    def test_detail_returns_ciphertext_and_kdf_metadata_only(self):
        res = bearer(self.token).get(detail_url("gmail.com"))
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["key"], "gmail.com")
        self.assertIn("ciphertext", body)
        self.assertEqual(body["kdf"], "pbkdf2-sha256")
        self.assertEqual(body["salt"], self.project.salt)
        self.assertEqual(body["iterations"], self.project.iterations)
        self.assertEqual(body["project_id"], self.project.public_id)
        self.assertNotIn("value", body)
        self.assertNotIn("plaintext", body)
        self.assertNotIn("passphrase", body)
        self.assertNotIn(PLAINTEXT, res.content.decode())

    def test_list_returns_key_names_without_ciphertext_or_values(self):
        res = bearer(self.token).get(LIST_URL)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["keys"], ["gmail.com"])
        self.assertEqual(body["kdf"], "pbkdf2-sha256")
        raw = res.content.decode()
        self.assertNotIn("ciphertext", raw)
        self.assertNotIn(PLAINTEXT, raw)

    def test_empty_project_lists_no_keys(self):
        empty, _ = make_project(self.user, name="empty")
        _, token = ProjectAPIKey.generate(empty)
        res = bearer(token).get(LIST_URL)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["keys"], [])

    def test_missing_secret_returns_404(self):
        res = bearer(self.token).get(detail_url("nope.com"))
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json(), {"detail": "Not found."})

    def test_path_key_with_slashes_resolves(self):
        add_secret(self.project, self.key, "ns/sub/token", plaintext="nested-value")
        res = bearer(self.token).get(detail_url("ns/sub/token"))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["key"], "ns/sub/token")
        self.assertNotIn("nested-value", res.content.decode())


class TenantIsolationTests(APITestCase):
    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.bob = User.objects.create_user(username="bob", password="pw")
        self.proj_a, self.key_a = make_project(self.alice, name="alpha")
        self.proj_b, self.key_b = make_project(self.bob, name="bravo")
        add_secret(self.proj_a, self.key_a, "alice.com", plaintext="alice-plaintext")
        add_secret(self.proj_b, self.key_b, "bob.com", plaintext="bob-plaintext")
        _, self.token_a = ProjectAPIKey.generate(self.proj_a)
        _, self.token_b = ProjectAPIKey.generate(self.proj_b)

    def test_project_a_key_cannot_read_project_b_secret(self):
        res = bearer(self.token_a).get(detail_url("bob.com"))
        self.assertEqual(res.status_code, 404)
        self.assertNotIn("bob-plaintext", res.content.decode())

    def test_list_shows_only_own_project_keys_and_metadata(self):
        res = bearer(self.token_a).get(LIST_URL)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["keys"], ["alice.com"])
        self.assertNotIn("bob.com", body["keys"])
        self.assertEqual(body["project_id"], self.proj_a.public_id)
        self.assertEqual(body["salt"], self.proj_a.salt)
        self.assertNotEqual(body["salt"], self.proj_b.salt)

    def test_other_tenant_key_reads_only_its_own_data(self):
        listing = bearer(self.token_b).get(LIST_URL)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["keys"], ["bob.com"])
        cross = bearer(self.token_b).get(detail_url("alice.com"))
        self.assertEqual(cross.status_code, 404)

    def test_same_key_name_across_tenants_stays_isolated(self):
        add_secret(self.proj_a, self.key_a, "shared.com", plaintext="alice-shared")
        add_secret(self.proj_b, self.key_b, "shared.com", plaintext="bob-shared")
        res_a = bearer(self.token_a).get(detail_url("shared.com"))
        res_b = bearer(self.token_b).get(detail_url("shared.com"))
        self.assertEqual(res_a.status_code, 200)
        self.assertEqual(res_b.status_code, 200)
        ct_a = res_a.json()["ciphertext"]
        ct_b = res_b.json()["ciphertext"]
        self.assertNotEqual(ct_a, ct_b)
        self.assertEqual(crypto.decrypt(self.key_a, ct_a), "alice-shared")
        self.assertEqual(crypto.decrypt(self.key_b, ct_b), "bob-shared")
        self.assertNotIn("alice-shared", res_b.content.decode())
        self.assertNotIn("bob-shared", res_a.content.decode())
