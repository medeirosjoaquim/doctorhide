from datetime import timedelta

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase

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
