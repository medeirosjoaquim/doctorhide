from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

from organizations.models import Membership, Organization
from .models import APIKey, ServiceAccount

User = get_user_model()


class APIKeyModelTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="admin", password="pw")
        self.sa = ServiceAccount.objects.create(name="billing-api", created_by=self.user)

    def test_verify_matches_only_correct_secret(self):
        key, token = APIKey.generate(self.sa)
        _, secret = APIKey.split_token(token)
        self.assertTrue(key.verify(secret))
        self.assertFalse(key.verify(secret + "x"))

    def test_secret_is_not_stored(self):
        key, token = APIKey.generate(self.sa)
        _, secret = APIKey.split_token(token)
        self.assertNotIn(secret, key.hashed_secret)

    def test_expired_key_is_inactive(self):
        key, _ = APIKey.generate(self.sa, expires_at=timezone.now() - timedelta(seconds=1))
        self.assertFalse(key.is_active())

    def test_revoked_key_is_inactive(self):
        key, _ = APIKey.generate(self.sa)
        key.revoke()
        self.assertFalse(key.is_active())

    def test_inactive_service_account_disables_key(self):
        key, _ = APIKey.generate(self.sa)
        self.sa.is_active = False
        self.sa.save()
        key.refresh_from_db()
        self.assertFalse(key.is_active())

    def test_split_token_rejects_garbage(self):
        self.assertEqual(APIKey.split_token("nope"), (None, None))
        self.assertEqual(APIKey.split_token("dh_live_onlyid"), (None, None))


class ServiceAccountOrganizationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="admin", password="pw")
        self.org = Organization.objects.create(name="Acme", slug="acme")
        Membership.objects.create(
            organization=self.org, user=self.user, role=Membership.ROLE_OWNER
        )

    def test_service_account_scoped_to_organization(self):
        sa = ServiceAccount.objects.create(
            name="billing-api", created_by=self.user, organization=self.org
        )
        self.assertEqual(sa.organization, self.org)
        self.assertIn(sa, self.org.service_accounts.all())

    def test_organization_optional(self):
        sa = ServiceAccount.objects.create(name="legacy-api", created_by=self.user)
        self.assertIsNone(sa.organization_id)


class WhoamiTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.sa = ServiceAccount.objects.create(name="billing-api", created_by=self.user)
        self.key, self.token = APIKey.generate(self.sa)

    def test_unauthenticated_is_rejected(self):
        self.assertEqual(self.client.get("/whoami").status_code, 401)

    def test_machine_principal(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        res = client.get("/whoami")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"type": "service_account", "name": "billing-api"})

    def test_human_principal(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        res = client.get("/whoami")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"type": "user", "username": "alice"})

    def test_revoked_key_is_rejected(self):
        self.key.revoke()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(client.get("/whoami").status_code, 401)


class APIKeyLastUsedAtThrottlingTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username="alice", password="pw")
        self.sa = ServiceAccount.objects.create(name="billing-api", created_by=self.user)
        self.key, self.token = APIKey.generate(self.sa)
        self.client = APIClient()

    def tearDown(self):
        cache.clear()

    def test_first_authentication_records_usage(self):
        """First API call should record last_used_at."""
        self.assertIsNone(self.key.last_used_at)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.client.get("/whoami")
        self.key.refresh_from_db()
        self.assertIsNotNone(self.key.last_used_at)

    def test_recent_authentication_skips_db_write(self):
        """If last_used_at is recent, a new authentication should skip the DB write."""
        # Set last_used_at to now
        now = timezone.now()
        self.key.last_used_at = now
        self.key.save()
        cache.clear()

        # Make request and capture the updated timestamp
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.client.get("/whoami")

        # last_used_at should not have changed (within a second)
        self.key.refresh_from_db()
        self.assertAlmostEqual(
            (self.key.last_used_at - now).total_seconds(),
            0,
            delta=1
        )

    def test_old_authentication_updates_usage(self):
        """If last_used_at is old, a new authentication should update it."""
        # Set last_used_at to 2 hours ago
        old_time = timezone.now() - timedelta(hours=2)
        self.key.last_used_at = old_time
        self.key.save()
        cache.clear()

        # Make request
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.client.get("/whoami")

        # last_used_at should have been updated
        self.key.refresh_from_db()
        self.assertGreater(self.key.last_used_at, old_time)

    def test_throttle_caching_prevents_duplicate_writes(self):
        """Multiple rapid requests should only write to DB once per throttle period."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

        # First request: writes to DB
        self.client.get("/whoami")
        self.key.refresh_from_db()
        first_last_used = self.key.last_used_at
        self.assertIsNotNone(first_last_used)

        # Immediately make another request
        self.client.get("/whoami")
        self.key.refresh_from_db()
        second_last_used = self.key.last_used_at

        # last_used_at should not have changed (same value)
        self.assertEqual(first_last_used, second_last_used)
