from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

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


class SecretRestoreForceDeleteAPITests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, self.key = make_project(self.user)
        _, token = ProjectAPIKey.generate(self.project)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + token)

    def _make_secret(self, key="gmail.com", value="v", deleted=False):
        secret = Secret.objects.create(
            project=self.project, key=key, ciphertext=crypto.encrypt(self.key, value)
        )
        if deleted:
            secret.soft_delete()
        return secret

    def test_restore_clears_deleted_at_and_reappears_in_list(self):
        secret = self._make_secret(deleted=True)
        url = reverse("api_secret_restore", args=[secret.key])
        res = self.client.post(url)
        self.assertEqual(res.status_code, 200)
        secret.refresh_from_db()
        self.assertIsNone(secret.deleted_at)
        listed = self.client.get(reverse("api_secrets_list"))
        self.assertIn(secret.key, listed.json()["keys"])

    def test_restore_nonexistent_key_is_404(self):
        res = self.client.post(reverse("api_secret_restore", args=["nope.com"]))
        self.assertEqual(res.status_code, 404)

    def test_restore_active_secret_is_404(self):
        secret = self._make_secret(deleted=False)
        res = self.client.post(reverse("api_secret_restore", args=[secret.key]))
        self.assertEqual(res.status_code, 404)

    def test_force_delete_removes_row(self):
        secret = self._make_secret(deleted=True)
        res = self.client.delete(reverse("api_secret_force_delete", args=[secret.key]))
        self.assertEqual(res.status_code, 204)
        self.assertFalse(Secret.objects.filter(id=secret.id).exists())

    def test_force_delete_active_secret_removes_row(self):
        secret = self._make_secret(deleted=False)
        res = self.client.delete(reverse("api_secret_force_delete", args=[secret.key]))
        self.assertEqual(res.status_code, 204)
        self.assertFalse(Secret.objects.filter(id=secret.id).exists())

    def test_force_delete_nonexistent_key_is_404(self):
        res = self.client.delete(reverse("api_secret_force_delete", args=["nope.com"]))
        self.assertEqual(res.status_code, 404)

    def test_restore_scoped_to_authenticated_project(self):
        other_project, other_key = make_project(self.user, name="staging")
        foreign = Secret.objects.create(
            project=other_project, key="x.com", ciphertext=crypto.encrypt(other_key, "y")
        )
        foreign.soft_delete()
        res = self.client.post(reverse("api_secret_restore", args=[foreign.key]))
        self.assertEqual(res.status_code, 404)
        foreign.refresh_from_db()
        self.assertIsNotNone(foreign.deleted_at)

    def test_force_delete_scoped_to_authenticated_project(self):
        other_project, other_key = make_project(self.user, name="staging")
        foreign = Secret.objects.create(
            project=other_project, key="x.com", ciphertext=crypto.encrypt(other_key, "y")
        )
        res = self.client.delete(reverse("api_secret_force_delete", args=[foreign.key]))
        self.assertEqual(res.status_code, 404)
        self.assertTrue(Secret.objects.filter(id=foreign.id).exists())

    def test_restore_requires_auth(self):
        secret = self._make_secret(deleted=True)
        anon = APIClient()
        res = anon.post(reverse("api_secret_restore", args=[secret.key]))
        self.assertEqual(res.status_code, 401)

    def test_force_delete_requires_auth(self):
        secret = self._make_secret(deleted=True)
        anon = APIClient()
        res = anon.delete(reverse("api_secret_force_delete", args=[secret.key]))
        self.assertEqual(res.status_code, 401)
