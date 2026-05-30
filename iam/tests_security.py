from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase, APITransactionTestCase

from .models import KEY_PREFIX, APIKey, ServiceAccount

User = get_user_model()

WHOAMI = "/whoami"


def auth_client(token):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


class LastUsedAtTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="admin", password="pw")
        self.sa = ServiceAccount.objects.create(name="billing-api", created_by=self.user)
        self.key, self.token = APIKey.generate(self.sa)

    def test_successful_auth_sets_last_used_at(self):
        self.assertIsNone(self.key.last_used_at)
        before = timezone.now()
        res = auth_client(self.token).get(WHOAMI)
        self.assertEqual(res.status_code, 200)
        self.key.refresh_from_db()
        self.assertIsNotNone(self.key.last_used_at)
        self.assertGreaterEqual(self.key.last_used_at, before)

    def test_failed_auth_leaves_last_used_at_unset(self):
        prefix, _ = APIKey.split_token(self.token)
        bad = f"{prefix}_wrongsecret"
        res = auth_client(bad).get(WHOAMI)
        self.assertEqual(res.status_code, 401)
        self.key.refresh_from_db()
        self.assertIsNone(self.key.last_used_at)


class HTTPAuthFailureTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.sa = ServiceAccount.objects.create(name="billing-api", created_by=self.user)
        self.key, self.token = APIKey.generate(self.sa)

    def test_expired_key_rejected(self):
        self.key.expires_at = timezone.now() - timedelta(seconds=1)
        self.key.save(update_fields=["expires_at"])
        res = auth_client(self.token).get(WHOAMI)
        self.assertEqual(res.status_code, 401)

    def test_inactive_service_account_rejected(self):
        self.sa.is_active = False
        self.sa.save(update_fields=["is_active"])
        res = auth_client(self.token).get(WHOAMI)
        self.assertEqual(res.status_code, 401)

    def test_valid_prefix_wrong_secret_rejected(self):
        prefix, _ = APIKey.split_token(self.token)
        res = auth_client(f"{prefix}_totallywrong").get(WHOAMI)
        self.assertEqual(res.status_code, 401)

    def test_garbage_non_prefixed_token_rejected(self):
        res = auth_client("not-a-real-token").get(WHOAMI)
        self.assertEqual(res.status_code, 401)

    def test_wellformed_token_with_no_db_row_rejected(self):
        ghost = f"{KEY_PREFIX}deadbeefdeadbeef_someplausiblesecretvalue"
        res = auth_client(ghost).get(WHOAMI)
        self.assertEqual(res.status_code, 401)

    def test_failure_modes_are_indistinguishable(self):
        prefix, _ = APIKey.split_token(self.token)
        responses = [
            auth_client(f"{prefix}_wrongsecret").get(WHOAMI),
            auth_client(f"{KEY_PREFIX}deadbeefdeadbeef_nope").get(WHOAMI),
            auth_client("garbagewithoutprefix").get(WHOAMI),
        ]
        for res in responses:
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.json()["detail"], "Invalid API key.")
        details = {res.json()["detail"] for res in responses}
        self.assertEqual(len(details), 1)


class MalformedHeaderTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="bob", password="pw")
        self.sa = ServiceAccount.objects.create(name="billing-api", created_by=self.user)
        self.key, self.token = APIKey.generate(self.sa)

    def test_bearer_with_no_token_rejected(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Bearer")
        self.assertEqual(client.get(WHOAMI).status_code, 401)

    def test_bearer_with_three_parts_rejected(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token} extra")
        self.assertEqual(client.get(WHOAMI).status_code, 401)

    def test_empty_bearer_token_trailing_space_rejected(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Bearer ")
        self.assertEqual(client.get(WHOAMI).status_code, 401)

    def test_non_bearer_scheme_falls_through_to_unauthenticated(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Basic {self.token}")
        res = client.get(WHOAMI)
        self.assertEqual(res.status_code, 401)
        self.assertNotIn("_auth_user_id", client.session)

    def test_lowercase_bearer_scheme_accepted(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"bearer {self.token}")
        res = client.get(WHOAMI)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["type"], "service_account")


class TenantIsolationTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", password="pw")
        self.sa_a = ServiceAccount.objects.create(name="service-a", created_by=self.owner)
        self.sa_b = ServiceAccount.objects.create(name="service-b", created_by=self.owner)
        self.key_a, self.token_a = APIKey.generate(self.sa_a)

    def test_key_authenticates_only_as_its_own_service_account(self):
        res = auth_client(self.token_a).get(WHOAMI)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"type": "service_account", "name": "service-a"})


class RoundTripTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="carol", password="pw")
        self.sa = ServiceAccount.objects.create(name="billing-api", created_by=self.user)

    def test_freshly_minted_token_authenticates(self):
        _, token = APIKey.generate(self.sa)
        res = auth_client(token).get(WHOAMI)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["name"], "billing-api")


class VerifyUnitTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="dave", password="pw")
        self.sa = ServiceAccount.objects.create(name="billing-api", created_by=self.user)

    def test_verify_uses_constant_time_compare(self):
        key, token = APIKey.generate(self.sa)
        _, secret = APIKey.split_token(token)
        with mock.patch("iam.models.hmac.compare_digest", wraps=__import__("hmac").compare_digest) as cd:
            self.assertTrue(key.verify(secret))
        cd.assert_called_once()

    def test_split_token_empty_secret_and_empty_public_id(self):
        self.assertEqual(APIKey.split_token(f"{KEY_PREFIX}abc_"), (None, None))
        self.assertEqual(APIKey.split_token(f"{KEY_PREFIX}_secret"), (None, None))

    def test_revoke_is_idempotent(self):
        key, _ = APIKey.generate(self.sa)
        key.revoke()
        first = key.revoked_at
        self.assertIsNotNone(first)
        key.revoke()
        self.assertEqual(key.revoked_at, first)

    def test_expires_at_equal_to_now_is_inactive(self):
        now = timezone.now()
        key, _ = APIKey.generate(self.sa, expires_at=now)
        with mock.patch("iam.models.timezone.now", return_value=now):
            self.assertFalse(key.is_active())


class PrefixUniquenessTests(APITransactionTestCase):
    def test_duplicate_prefix_raises_integrity_error(self):
        user = User.objects.create_user(username="erin", password="pw")
        sa = ServiceAccount.objects.create(name="billing-api", created_by=user)
        key, _ = APIKey.generate(sa)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                APIKey.objects.create(
                    service_account=sa,
                    prefix=key.prefix,
                    hashed_secret="x" * 64,
                    last_four="abcd",
                )
