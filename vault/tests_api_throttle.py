from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from . import crypto
from .models import Project, ProjectAPIKey

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


@override_settings(
    REST_FRAMEWORK={
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "iam.authentication.APIKeyAuthentication",
            "rest_framework.authentication.SessionAuthentication",
        ],
        "DEFAULT_PERMISSION_CLASSES": [
            "rest_framework.permissions.IsAuthenticated",
        ],
        "DEFAULT_THROTTLE_RATES": {"vault_api": "3/min"},
    }
)
class VaultApiThrottleTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(username="throttle", password="pw")
        self.salt = crypto.generate_salt()
        self.derived = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            public_id=Project.new_public_id(),
            name="throttleproj",
        )
        env = self.project.default_environment
        env.salt = self.salt
        env = self.project.default_environment

        env.verifier = crypto.make_verifier(self.derived)
        env.save(update_fields=["salt", "verifier"])
        self.api_key, self.token = ProjectAPIKey.generate(self.project)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def tearDown(self):
        cache.clear()

    def test_exceeding_rate_returns_429(self):
        url = reverse("api_secrets_list")
        for _ in range(3):
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 200)
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 429)
