from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.plugins.otp_totp.models import TOTPDevice

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


def otp_login(client, user):
    """Log in and mark the session OTP-verified the way django_otp does."""
    device = TOTPDevice.objects.create(user=user, name="default", confirmed=True)
    client.force_login(user)
    session = client.session
    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    return device


class ProjectCreateViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        otp_login(self.client, self.user)
        self.url = reverse("vault:create")

    def test_valid_create_sets_crypto_fields_and_autounlocks(self):
        res = self.client.post(self.url, {"name": "prod", "passphrase": "longpass1"})
        project = Project.objects.get(owner=self.user, name="prod")
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.url, reverse("vault:detail", args=[project.public_id]))
        self.assertTrue(project.salt)
        self.assertEqual(project.iterations, crypto.DEFAULT_ITERATIONS)
        key = crypto.derive_key("longpass1", project.salt, project.iterations)
        self.assertTrue(crypto.verify_key(key, project.verifier))
        self.assertIn(project.public_id, self.client.session["vault_keys"])

    def test_missing_name_rerenders_with_error(self):
        res = self.client.post(self.url, {"name": "", "passphrase": "longpass1"})
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Project name is required.")
        self.assertFalse(Project.objects.filter(owner=self.user).exists())

    def test_short_passphrase_rerenders_with_error(self):
        res = self.client.post(self.url, {"name": "prod", "passphrase": "short"})
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Salt must be at least 8 characters.")
        self.assertFalse(Project.objects.filter(owner=self.user).exists())

    def test_duplicate_name_same_owner_rerenders_not_500(self):
        make_project(self.user, name="prod")
        res = self.client.post(self.url, {"name": "prod", "passphrase": "longpass1"})
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "You already have a project with that name.")
        self.assertEqual(Project.objects.filter(owner=self.user, name="prod").count(), 1)

    def test_passphrase_never_persisted(self):
        self.client.post(self.url, {"name": "prod", "passphrase": "longpass1"})
        project = Project.objects.get(owner=self.user, name="prod")
        self.assertNotIn("longpass1", project.salt)
        self.assertNotIn("longpass1", project.verifier)
        self.assertNotIn("longpass1", project.name)
        self.assertNotIn("longpass1", project.public_id)


class ProjectUniqueTogetherModelTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.bob = User.objects.create_user(username="bob", password="pw")

    def test_same_owner_same_name_raises_integrity_error(self):
        make_project(self.alice, name="prod")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                make_project(self.alice, name="prod")

    def test_different_owner_same_name_allowed(self):
        make_project(self.alice, name="prod")
        project, _ = make_project(self.bob, name="prod")
        self.assertEqual(Project.objects.filter(name="prod").count(), 2)
        self.assertEqual(project.owner, self.bob)


class ProjectLockUnlockViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        otp_login(self.client, self.user)
        self.project, self.key = make_project(self.user)
        self.detail_url = reverse("vault:detail", args=[self.project.public_id])

    def _unlock(self, passphrase=PASSPHRASE):
        return self.client.post(
            reverse("vault:unlock", args=[self.project.public_id]),
            {"passphrase": passphrase},
        )

    def test_unlock_correct_passphrase_stores_session_key(self):
        res = self._unlock()
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.url, self.detail_url)
        stored = self.client.session["vault_keys"][self.project.public_id]
        self.assertEqual(stored, self.key.decode())
        detail = self.client.get(self.detail_url)
        self.assertTrue(detail.context["unlocked"])

    def test_unlock_wrong_passphrase_rejected(self):
        res = self._unlock(passphrase="totally-wrong")
        self.assertEqual(res.status_code, 302)
        msgs = [m.message for m in self.client.get(self.detail_url).context["messages"]]
        self.assertIn("Wrong salt.", msgs)
        self.assertNotIn(self.project.public_id, self.client.session.get("vault_keys", {}))
        detail = self.client.get(self.detail_url)
        self.assertFalse(detail.context["unlocked"])

    def test_lock_clears_session_key(self):
        self._unlock()
        res = self.client.post(reverse("vault:lock", args=[self.project.public_id]))
        self.assertEqual(res.status_code, 302)
        self.assertNotIn(self.project.public_id, self.client.session.get("vault_keys", {}))
        detail = self.client.get(self.detail_url)
        self.assertFalse(detail.context["unlocked"])
        self.assertEqual(list(detail.context["secrets"]), [])

    def test_locked_project_cannot_add_secrets(self):
        res = self.client.post(
            reverse("vault:secret_add", args=[self.project.public_id]),
            {"key": "gmail.com", "value": "abc123"},
        )
        self.assertEqual(res.status_code, 302)
        msgs = [m.message for m in self.client.get(self.detail_url).context["messages"]]
        self.assertIn("Unlock the project first.", msgs)
        self.assertEqual(self.project.secrets.count(), 0)

    def test_locked_detail_does_not_expose_secrets(self):
        Secret.objects.create(
            project=self.project, key="gmail.com", ciphertext=crypto.encrypt(self.key, "abc123")
        )
        detail = self.client.get(self.detail_url)
        self.assertFalse(detail.context["unlocked"])
        self.assertEqual(list(detail.context["secrets"]), [])
        self.assertNotContains(detail, "abc123")


class SecretLifecycleViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        otp_login(self.client, self.user)
        self.project, self.key = make_project(self.user)
        self.detail_url = reverse("vault:detail", args=[self.project.public_id])
        self.add_url = reverse("vault:secret_add", args=[self.project.public_id])
        # unlock for the session
        self.client.post(
            reverse("vault:unlock", args=[self.project.public_id]),
            {"passphrase": PASSPHRASE},
        )

    def test_add_creates_secret_whose_ciphertext_decrypts(self):
        res = self.client.post(self.add_url, {"key": "gmail.com", "value": "abc123"})
        self.assertEqual(res.status_code, 302)
        secret = Secret.objects.get(project=self.project, key="gmail.com")
        self.assertNotIn("abc123", secret.ciphertext)
        self.assertEqual(crypto.decrypt(self.key, secret.ciphertext), "abc123")

    def test_add_existing_key_updates_without_duplicate(self):
        self.client.post(self.add_url, {"key": "gmail.com", "value": "abc123"})
        self.client.post(self.add_url, {"key": "gmail.com", "value": "newvalue"})
        secrets = Secret.objects.filter(project=self.project, key="gmail.com")
        self.assertEqual(secrets.count(), 1)
        self.assertEqual(crypto.decrypt(self.key, secrets.first().ciphertext), "newvalue")

    def test_add_missing_value_creates_nothing(self):
        res = self.client.post(self.add_url, {"key": "gmail.com", "value": ""})
        self.assertEqual(res.status_code, 302)
        msgs = [m.message for m in self.client.get(self.detail_url).context["messages"]]
        self.assertIn("Both key and value are required.", msgs)
        self.assertEqual(self.project.secrets.count(), 0)

    def test_delete_removes_only_target_secret(self):
        s1 = Secret.objects.create(
            project=self.project, key="a.com", ciphertext=crypto.encrypt(self.key, "1")
        )
        s2 = Secret.objects.create(
            project=self.project, key="b.com", ciphertext=crypto.encrypt(self.key, "2")
        )
        res = self.client.post(
            reverse("vault:secret_delete", args=[self.project.public_id, s1.id])
        )
        self.assertEqual(res.status_code, 302)
        # Soft delete: the row remains but is excluded from the active set.
        self.assertFalse(
            Secret.objects.filter(id=s1.id, deleted_at__isnull=True).exists()
        )
        self.assertTrue(
            Secret.objects.filter(id=s2.id, deleted_at__isnull=True).exists()
        )

    def test_delete_secret_from_other_project_is_noop(self):
        other_project, other_key = make_project(self.user, name="staging")
        foreign = Secret.objects.create(
            project=other_project, key="x.com", ciphertext=crypto.encrypt(other_key, "y")
        )
        res = self.client.post(
            reverse("vault:secret_delete", args=[self.project.public_id, foreign.id])
        )
        self.assertEqual(res.status_code, 302)
        self.assertTrue(Secret.objects.filter(id=foreign.id).exists())


class APIKeyMintRevokeViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        otp_login(self.client, self.user)
        self.project, self.key = make_project(self.user)
        self.detail_url = reverse("vault:detail", args=[self.project.public_id])

    def test_mint_shows_token_once_and_stores_only_hash(self):
        res = self.client.post(reverse("vault:api_key_create", args=[self.project.public_id]))
        self.assertEqual(res.status_code, 302)
        token = self.client.session["vault_new_api_key"]
        self.assertTrue(token.startswith("dhk_"))

        first = self.client.get(self.detail_url)
        self.assertEqual(first.context["new_api_key"], token)
        # popped from session on the first detail GET
        self.assertIsNone(self.client.session.get("vault_new_api_key"))
        second = self.client.get(self.detail_url)
        self.assertIsNone(second.context["new_api_key"])

        api_key = ProjectAPIKey.objects.get(project=self.project)
        _, secret = ProjectAPIKey.split_token(token)
        self.assertNotIn(secret, api_key.hashed_secret)
        self.assertNotEqual(api_key.hashed_secret, secret)
        self.assertEqual(api_key.last_four, secret[-4:])
        self.assertTrue(api_key.verify(secret))

    def test_revoke_sets_revoked_at_and_deactivates(self):
        api_key, _ = ProjectAPIKey.generate(self.project)
        self.assertTrue(api_key.is_active())
        res = self.client.post(
            reverse("vault:api_key_revoke", args=[self.project.public_id, api_key.id])
        )
        self.assertEqual(res.status_code, 302)
        api_key.refresh_from_db()
        self.assertIsNotNone(api_key.revoked_at)
        self.assertFalse(api_key.is_active())


class ProjectAPIKeyModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, _ = make_project(self.user)

    def test_generate_returns_token_and_verify(self):
        api_key, token = ProjectAPIKey.generate(self.project)
        self.assertTrue(token.startswith("dhk_"))
        _, secret = ProjectAPIKey.split_token(token)
        self.assertTrue(api_key.verify(secret))
        self.assertFalse(api_key.verify("wrong-secret"))

    def test_is_active_transitions(self):
        api_key, _ = ProjectAPIKey.generate(self.project)
        self.assertTrue(api_key.is_active())
        api_key.revoke()
        self.assertFalse(api_key.is_active())

    def test_expired_key_inactive(self):
        api_key, _ = ProjectAPIKey.generate(self.project)
        api_key.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        api_key.save(update_fields=["expires_at"])
        self.assertFalse(api_key.is_active())

    def test_revoke_is_idempotent(self):
        api_key, _ = ProjectAPIKey.generate(self.project)
        api_key.revoke()
        first = api_key.revoked_at
        api_key.revoke()
        self.assertEqual(api_key.revoked_at, first)

    def test_split_token_rejects_bad_tokens(self):
        self.assertEqual(ProjectAPIKey.split_token("nope_abc_def"), (None, None))
        self.assertEqual(ProjectAPIKey.split_token("dhk_onlyprefix"), (None, None))
        self.assertEqual(ProjectAPIKey.split_token("dhk_"), (None, None))
        prefix, secret = ProjectAPIKey.split_token("dhk_abcd_thesecret")
        self.assertEqual(prefix, "dhk_abcd")
        self.assertEqual(secret, "thesecret")


class TenantIsolationViewTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.bob = User.objects.create_user(username="bob", password="pw")
        otp_login(self.client, self.alice)
        self.bob_project, self.bob_key = make_project(self.bob, name="bobs-prod")
        self.bob_secret = Secret.objects.create(
            project=self.bob_project, key="b.com", ciphertext=crypto.encrypt(self.bob_key, "v")
        )
        self.bob_api_key, _ = ProjectAPIKey.generate(self.bob_project)
        self.pid = self.bob_project.public_id

    def test_detail_404_cross_owner(self):
        res = self.client.get(reverse("vault:detail", args=[self.pid]))
        self.assertEqual(res.status_code, 404)

    def test_unlock_404_cross_owner(self):
        res = self.client.post(
            reverse("vault:unlock", args=[self.pid]), {"passphrase": PASSPHRASE}
        )
        self.assertEqual(res.status_code, 404)

    def test_lock_404_cross_owner(self):
        res = self.client.post(reverse("vault:lock", args=[self.pid]))
        self.assertEqual(res.status_code, 404)

    def test_secret_add_404_cross_owner(self):
        res = self.client.post(
            reverse("vault:secret_add", args=[self.pid]), {"key": "k", "value": "v"}
        )
        self.assertEqual(res.status_code, 404)
        self.assertEqual(self.bob_project.secrets.count(), 1)

    def test_secret_delete_404_cross_owner(self):
        res = self.client.post(
            reverse("vault:secret_delete", args=[self.pid, self.bob_secret.id])
        )
        self.assertEqual(res.status_code, 404)
        self.assertTrue(Secret.objects.filter(id=self.bob_secret.id).exists())

    def test_api_key_create_404_cross_owner(self):
        res = self.client.post(reverse("vault:api_key_create", args=[self.pid]))
        self.assertEqual(res.status_code, 404)
        self.assertEqual(self.bob_project.api_keys.count(), 1)

    def test_api_key_revoke_404_cross_owner(self):
        res = self.client.post(
            reverse("vault:api_key_revoke", args=[self.pid, self.bob_api_key.id])
        )
        self.assertEqual(res.status_code, 404)
        self.bob_api_key.refresh_from_db()
        self.assertIsNone(self.bob_api_key.revoked_at)

    def test_projects_list_scopes_to_owner(self):
        make_project(self.alice, name="alices-prod")
        res = self.client.get(reverse("vault:projects"))
        names = {p.name for p in res.context["projects"]}
        self.assertIn("alices-prod", names)
        self.assertNotIn("bobs-prod", names)


class OTPGatingViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        self.project, _ = make_project(self.user)
        self.detail_url = reverse("vault:detail", args=[self.project.public_id])

    def test_unauthenticated_redirected_to_login(self):
        res = self.client.get(reverse("vault:projects"))
        self.assertEqual(res.status_code, 302)
        # settings.LOGIN_URL is the URL *name* ("accounts:login"); the redirect
        # carries the resolved path, so compare against the reversed path.
        self.assertIn(reverse(settings.LOGIN_URL), res.url)

    def test_authenticated_without_otp_redirected(self):
        self.client.force_login(self.user)
        res = self.client.get(self.detail_url)
        self.assertEqual(res.status_code, 302)
        self.assertNotEqual(res.status_code, 200)


class PostOnlyMutationViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        otp_login(self.client, self.user)
        self.project, self.key = make_project(self.user)
        self.client.post(
            reverse("vault:unlock", args=[self.project.public_id]),
            {"passphrase": PASSPHRASE},
        )

    def test_get_unlock_does_not_change_state(self):
        # unlock GET on a locked project: lock first
        self.client.post(reverse("vault:lock", args=[self.project.public_id]))
        res = self.client.get(reverse("vault:unlock", args=[self.project.public_id]))
        self.assertEqual(res.status_code, 302)
        self.assertNotIn(self.project.public_id, self.client.session.get("vault_keys", {}))

    def test_get_secret_add_creates_nothing(self):
        res = self.client.get(reverse("vault:secret_add", args=[self.project.public_id]))
        self.assertEqual(res.status_code, 302)
        self.assertEqual(self.project.secrets.count(), 0)

    def test_get_secret_delete_deletes_nothing(self):
        secret = Secret.objects.create(
            project=self.project, key="a.com", ciphertext=crypto.encrypt(self.key, "1")
        )
        res = self.client.get(
            reverse("vault:secret_delete", args=[self.project.public_id, secret.id])
        )
        self.assertEqual(res.status_code, 302)
        self.assertTrue(Secret.objects.filter(id=secret.id).exists())

    def test_get_api_key_create_mints_nothing(self):
        res = self.client.get(reverse("vault:api_key_create", args=[self.project.public_id]))
        self.assertEqual(res.status_code, 302)
        self.assertEqual(self.project.api_keys.count(), 0)

    def test_get_api_key_revoke_does_not_revoke(self):
        api_key, _ = ProjectAPIKey.generate(self.project)
        res = self.client.get(
            reverse("vault:api_key_revoke", args=[self.project.public_id, api_key.id])
        )
        self.assertEqual(res.status_code, 302)
        api_key.refresh_from_db()
        self.assertIsNone(api_key.revoked_at)
