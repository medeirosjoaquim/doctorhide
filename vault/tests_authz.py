"""Authorization, ownership-isolation, lock/unlock state transitions and
API-key lifecycle tests for the vault web views (vault/views.py) and the REST
secrets endpoint. These cover the security and lifecycle states left uncovered
by vault/tests.py.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from rest_framework.test import APIClient, APITestCase

from . import crypto
from .models import Project, ProjectAPIKey, Secret
from .views import SESSION_KEYS, NEW_API_KEY_SESSION

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


def make_project(owner, name="prod", passphrase=PASSPHRASE):
    salt = crypto.generate_salt()
    key = crypto.derive_key(passphrase, salt)
    project = Project.objects.create(
        owner=owner,
        public_id=Project.new_public_id(),
        name=name,
        salt=salt,
        verifier=crypto.make_verifier(key),
    )
    return project, key


def make_secret(project, key_material, name="gmail.com", value="abc123"):
    return Secret.objects.create(
        project=project, key=name, ciphertext=crypto.encrypt(key_material, value)
    )


def verified_login(client, user):
    """Log a user in with an OTP-verified session so @otp_required passes.

    django_otp's otp_required consults request.user.is_verified(), which is True
    when an OTP device id is on the session. We attach a confirmed TOTP device
    and place its persistent id on the session, mirroring what otp login does.
    """
    from django_otp.plugins.otp_static.models import StaticDevice

    client.force_login(user)
    device = StaticDevice.objects.create(user=user, name="backup", confirmed=True)
    session = client.session
    session[device.__module__ + "." + device.__class__.__name__] = ([str(device.id)],)
    # django_otp middleware reads otp_device_id off the session.
    from django_otp import DEVICE_ID_SESSION_KEY

    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    return device


# ---------------------------------------------------------------------------
# Web view: authentication / OTP gating
# ---------------------------------------------------------------------------

class VaultGatingTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", password="pw")
        self.project, self.key = make_project(self.owner)

    def test_anonymous_projects_list_redirected(self):
        res = self.client.get(reverse("vault:projects"))
        self.assertEqual(res.status_code, 302)
        self.assertNotIn(self.project.name, res.content.decode())

    def test_otp_unverified_user_detail_redirected(self):
        # logged in by password only, no verified OTP device on the session
        self.client.force_login(self.owner)
        res = self.client.get(reverse("vault:detail", kwargs={"public_id": self.project.public_id}))
        self.assertEqual(res.status_code, 302)

    def test_verified_owner_loads_list_and_detail(self):
        verified_login(self.client, self.owner)
        list_res = self.client.get(reverse("vault:projects"))
        self.assertEqual(list_res.status_code, 200)
        self.assertContains(list_res, self.project.name)
        detail_res = self.client.get(
            reverse("vault:detail", kwargs={"public_id": self.project.public_id})
        )
        self.assertEqual(detail_res.status_code, 200)
        self.assertEqual(detail_res.context["project"].pk, self.project.pk)


# ---------------------------------------------------------------------------
# Web view: tenant isolation
# ---------------------------------------------------------------------------

class VaultTenantIsolationTests(TestCase):
    """The owner filter in _get_project() is the only tenant boundary for every
    web route. These exhaustively probe that boundary: Alice (authenticated +
    OTP-verified) must never read or mutate any of Bob's projects, secrets, or
    keys, regardless of which identifier she supplies.
    """

    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="pw")
        self.bob = User.objects.create_user(username="bob", password="pw")
        self.bob_project, self.bob_key = make_project(self.bob, name="bobs-prod")
        self.bob_secret = make_secret(self.bob_project, self.bob_key)
        self.bob_apikey, self.bob_token = ProjectAPIKey.generate(self.bob_project)
        # Alice also owns a project, so a session/cache leak would be observable.
        self.alice_project, self.alice_key = make_project(self.alice, name="alices-prod")
        verified_login(self.client, self.alice)

    # --- read paths ---------------------------------------------------------

    def test_cannot_view_other_users_detail(self):
        res = self.client.get(
            reverse("vault:detail", kwargs={"public_id": self.bob_project.public_id})
        )
        self.assertEqual(res.status_code, 404)
        self.assertNotIn(self.bob_project.name, res.content.decode())

    def test_list_only_shows_own_projects(self):
        res = self.client.get(reverse("vault:projects"))
        self.assertEqual(res.status_code, 200)
        listed = list(res.context["projects"])
        self.assertIn(self.alice_project, listed)
        self.assertNotIn(self.bob_project, listed)
        self.assertNotContains(res, "bobs-prod")

    def test_nonexistent_public_id_404(self):
        res = self.client.get(reverse("vault:detail", kwargs={"public_id": "proj_doesnotexist"}))
        self.assertEqual(res.status_code, 404)

    def test_owner_filter_not_just_public_id_lookup(self):
        # Same public_id, wrong owner -> still 404 (the owner clause must apply).
        self.assertTrue(Project.objects.filter(public_id=self.bob_project.public_id).exists())
        res = self.client.get(
            reverse("vault:detail", kwargs={"public_id": self.bob_project.public_id})
        )
        self.assertEqual(res.status_code, 404)

    # --- mutating paths -----------------------------------------------------

    def test_mutating_routes_on_foreign_project_all_404(self):
        pid = self.bob_project.public_id
        posts = [
            (reverse("vault:unlock", kwargs={"public_id": pid}), {"passphrase": PASSPHRASE}),
            (reverse("vault:lock", kwargs={"public_id": pid}), {}),
            (reverse("vault:secret_add", kwargs={"public_id": pid}), {"key": "X", "value": "Y"}),
            (reverse("vault:api_key_create", kwargs={"public_id": pid}), {}),
            (
                reverse("vault:secret_delete", kwargs={"public_id": pid, "secret_id": self.bob_secret.id}),
                {},
            ),
            (
                reverse("vault:api_key_revoke", kwargs={"public_id": pid, "key_id": self.bob_apikey.id}),
                {},
            ),
        ]
        for url, data in posts:
            res = self.client.post(url, data)
            self.assertEqual(res.status_code, 404, msg=url)

        # Bob's state is entirely untouched.
        self.assertTrue(Secret.objects.filter(pk=self.bob_secret.pk).exists())
        self.bob_apikey.refresh_from_db()
        self.assertTrue(self.bob_apikey.is_active())
        self.assertEqual(self.bob_project.secrets.count(), 1)
        self.assertEqual(self.bob_project.api_keys.count(), 1)

    def test_foreign_unlock_does_not_leak_into_alice_session(self):
        # Even posting Bob's *correct* passphrase to Bob's project must 404 and
        # cache nothing in Alice's session.
        res = self.client.post(
            reverse("vault:unlock", kwargs={"public_id": self.bob_project.public_id}),
            {"passphrase": PASSPHRASE},
        )
        self.assertEqual(res.status_code, 404)
        self.assertNotIn(self.bob_project.public_id, self.client.session.get(SESSION_KEYS, {}))

    def test_cannot_add_secret_to_foreign_project(self):
        res = self.client.post(
            reverse("vault:secret_add", kwargs={"public_id": self.bob_project.public_id}),
            {"key": "injected", "value": "evil"},
        )
        self.assertEqual(res.status_code, 404)
        self.assertFalse(Secret.objects.filter(project=self.bob_project, key="injected").exists())

    def test_cannot_delete_foreign_secret(self):
        url = reverse(
            "vault:secret_delete",
            kwargs={"public_id": self.bob_project.public_id, "secret_id": self.bob_secret.id},
        )
        res = self.client.post(url)
        self.assertEqual(res.status_code, 404)
        self.assertTrue(Secret.objects.filter(pk=self.bob_secret.pk).exists())

    def test_cannot_delete_foreign_secret_via_own_project_id(self):
        # Confused-deputy attempt: Alice supplies HER project's public_id but
        # Bob's secret id. The secret belongs to Bob's project, so
        # project.secrets.filter(id=...) matches nothing and Bob's secret lives.
        url = reverse(
            "vault:secret_delete",
            kwargs={"public_id": self.alice_project.public_id, "secret_id": self.bob_secret.id},
        )
        res = self.client.post(url)
        self.assertIn(res.status_code, (302, 404))
        self.assertTrue(Secret.objects.filter(pk=self.bob_secret.pk).exists())

    def test_cannot_revoke_foreign_key_via_own_project_id(self):
        # Alice's own project id + Bob's key id: api_keys filter is project-scoped,
        # so Bob's key is never matched and stays active.
        url = reverse(
            "vault:api_key_revoke",
            kwargs={"public_id": self.alice_project.public_id, "key_id": self.bob_apikey.id},
        )
        res = self.client.post(url)
        self.assertIn(res.status_code, (302, 404))
        self.bob_apikey.refresh_from_db()
        self.assertTrue(self.bob_apikey.is_active())

    def test_cannot_mint_key_on_foreign_project(self):
        res = self.client.post(
            reverse("vault:api_key_create", kwargs={"public_id": self.bob_project.public_id})
        )
        self.assertEqual(res.status_code, 404)
        self.assertEqual(self.bob_project.api_keys.count(), 1)
        self.assertIsNone(self.client.session.get(NEW_API_KEY_SESSION))

    # --- cross-principal: API key is single-project scoped ------------------

    def test_bob_api_key_cannot_read_alice_secrets(self):
        # Bob's REST key authenticates as Bob's project only; it can never reach
        # Alice's secrets even though both belong to different owners.
        make_secret(self.alice_project, self.alice_key, name="alice-only", value="topsecret")
        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {self.bob_token}")
        res = api.get("/api/secrets")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["project_id"], self.bob_project.public_id)
        self.assertNotIn("alice-only", res.json()["keys"])
        self.assertEqual(api.get("/api/secrets/alice-only").status_code, 404)


# ---------------------------------------------------------------------------
# Web view: unlock / lock transitions + reveal
# ---------------------------------------------------------------------------

class VaultLockUnlockTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", password="pw")
        self.project, self.key = make_project(self.owner)
        self.secret = make_secret(self.project, self.key, name="db", value="hunter2")
        verified_login(self.client, self.owner)

    def _detail(self, **qs):
        url = reverse("vault:detail", kwargs={"public_id": self.project.public_id})
        if qs:
            from urllib.parse import urlencode

            url += "?" + urlencode(qs)
        return self.client.get(url)

    def _unlock(self, passphrase):
        return self.client.post(
            reverse("vault:unlock", kwargs={"public_id": self.project.public_id}),
            {"passphrase": passphrase},
        )

    def test_unlock_correct_passphrase_unlocks_and_reveals(self):
        res = self._unlock(PASSPHRASE)
        self.assertEqual(res.status_code, 302)
        detail = self._detail()
        self.assertTrue(detail.context["unlocked"])
        revealed = self._detail(reveal=self.secret.id)
        self.assertContains(revealed, "hunter2")

    def test_unlock_wrong_passphrase_rejected(self):
        res = self._unlock("totally-wrong")
        self.assertEqual(res.status_code, 302)
        # No key cached for this project.
        self.assertNotIn(self.project.public_id, self.client.session.get(SESSION_KEYS, {}))
        detail = self._detail(reveal=self.secret.id)
        self.assertFalse(detail.context["unlocked"])
        self.assertNotContains(detail, "hunter2")

    def test_reveal_while_locked_returns_no_plaintext(self):
        detail = self._detail(reveal=self.secret.id)
        self.assertEqual(detail.status_code, 200)
        self.assertFalse(detail.context["unlocked"])
        self.assertEqual(detail.context["secrets"], [])
        self.assertNotContains(detail, "hunter2")

    def test_lock_transition_forgets_key(self):
        self._unlock(PASSPHRASE)
        self.client.post(reverse("vault:lock", kwargs={"public_id": self.project.public_id}))
        self.assertNotIn(self.project.public_id, self.client.session.get(SESSION_KEYS, {}))
        detail = self._detail(reveal=self.secret.id)
        self.assertFalse(detail.context["unlocked"])
        self.assertNotContains(detail, "hunter2")

    def test_unlocking_one_project_does_not_unlock_another(self):
        other, _ = make_project(self.owner, name="staging", passphrase="other-pass-99")
        self._unlock(PASSPHRASE)
        other_detail = self.client.get(
            reverse("vault:detail", kwargs={"public_id": other.public_id})
        )
        self.assertFalse(other_detail.context["unlocked"])

    def test_reveal_only_targets_matching_secret_id(self):
        make_secret(self.project, self.key, name="other", value="zzz-other-9")
        self._unlock(PASSPHRASE)
        detail = self._detail(reveal=self.secret.id)
        revealed = {s["obj"].key: s["value"] for s in detail.context["secrets"]}
        self.assertEqual(revealed["db"], "hunter2")
        self.assertIsNone(revealed["other"])
        self.assertNotContains(detail, "zzz-other-9")


# ---------------------------------------------------------------------------
# Web view: project_create
# ---------------------------------------------------------------------------

class VaultProjectCreateTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", password="pw")
        self.other = User.objects.create_user(username="other", password="pw")
        verified_login(self.client, self.owner)
        self.url = reverse("vault:create")

    def test_create_happy_path_auto_unlocks(self):
        res = self.client.post(self.url, {"name": "newproj", "passphrase": "longenough1"})
        self.assertEqual(res.status_code, 302)
        proj = Project.objects.get(owner=self.owner, name="newproj")
        self.assertEqual(res.url, reverse("vault:detail", kwargs={"public_id": proj.public_id}))
        self.assertTrue(proj.salt)
        self.assertTrue(proj.verifier)
        self.assertIn(proj.public_id, self.client.session.get(SESSION_KEYS, {}))

    def test_create_rejects_empty_name(self):
        res = self.client.post(self.url, {"name": "", "passphrase": "longenough1"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.context["error"], "Project name is required.")
        self.assertFalse(Project.objects.filter(owner=self.owner).exists())

    def test_create_rejects_short_passphrase(self):
        res = self.client.post(self.url, {"name": "shorty", "passphrase": "short"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.context["error"], "Salt must be at least 8 characters.")
        self.assertFalse(Project.objects.filter(owner=self.owner, name="shorty").exists())

    def test_create_rejects_duplicate_name_same_owner(self):
        make_project(self.owner, name="dup")
        res = self.client.post(self.url, {"name": "dup", "passphrase": "longenough1"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.context["error"], "You already have a project with that name.")
        self.assertEqual(Project.objects.filter(owner=self.owner, name="dup").count(), 1)

    def test_same_name_allowed_for_different_owner(self):
        make_project(self.other, name="sharedname")
        res = self.client.post(self.url, {"name": "sharedname", "passphrase": "longenough1"})
        self.assertEqual(res.status_code, 302)
        self.assertTrue(Project.objects.filter(owner=self.owner, name="sharedname").exists())
        self.assertTrue(Project.objects.filter(owner=self.other, name="sharedname").exists())

    def test_create_never_persists_passphrase(self):
        phrase = "zk-never-store-me"
        self.client.post(self.url, {"name": "zkproj", "passphrase": phrase})
        proj = Project.objects.get(owner=self.owner, name="zkproj")
        self.assertNotIn(phrase, proj.salt)
        self.assertNotIn(phrase, proj.verifier)
        self.assertNotIn(phrase, repr(proj.__dict__))


# ---------------------------------------------------------------------------
# Web view: secret_add / secret_delete behaviour
# ---------------------------------------------------------------------------

class VaultSecretMutationTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", password="pw")
        self.project, self.key = make_project(self.owner)
        verified_login(self.client, self.owner)
        self.add_url = reverse("vault:secret_add", kwargs={"public_id": self.project.public_id})

    def _unlock(self):
        self.client.post(
            reverse("vault:unlock", kwargs={"public_id": self.project.public_id}),
            {"passphrase": PASSPHRASE},
        )

    def test_secret_add_creates_encrypted_secret_when_unlocked(self):
        self._unlock()
        self.client.post(self.add_url, {"key": "TOKEN", "value": "plaintextval"})
        secret = Secret.objects.get(project=self.project, key="TOKEN")
        self.assertNotIn("plaintextval", secret.ciphertext)
        self.assertEqual(crypto.decrypt(self.key, secret.ciphertext), "plaintextval")

    def test_secret_add_overwrites_without_duplicate(self):
        self._unlock()
        self.client.post(self.add_url, {"key": "TOKEN", "value": "first-value"})
        self.client.post(self.add_url, {"key": "TOKEN", "value": "second-value"})
        qs = Secret.objects.filter(project=self.project, key="TOKEN")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(crypto.decrypt(self.key, qs.first().ciphertext), "second-value")

    def test_secret_add_while_locked_rejected(self):
        res = self.client.post(self.add_url, {"key": "NOPE", "value": "v"}, follow=True)
        self.assertFalse(Secret.objects.filter(project=self.project, key="NOPE").exists())
        msgs = [m.message for m in res.context["messages"]]
        self.assertIn("Unlock the project first.", msgs)

    def test_secret_add_requires_both_key_and_value(self):
        self._unlock()
        self.client.post(self.add_url, {"key": "ONLYKEY", "value": ""})
        self.assertFalse(Secret.objects.filter(project=self.project, key="ONLYKEY").exists())
        self.client.post(self.add_url, {"key": "", "value": "onlyval"})
        self.assertFalse(Secret.objects.filter(project=self.project, key="").exists())

    def test_secret_delete_removes_only_target(self):
        keep = make_secret(self.project, self.key, name="KEEP", value="keepme")
        gone = make_secret(self.project, self.key, name="GONE", value="byebye")
        url = reverse(
            "vault:secret_delete",
            kwargs={"public_id": self.project.public_id, "secret_id": gone.id},
        )
        self.client.post(url)
        self.assertFalse(Secret.objects.filter(pk=gone.pk).exists())
        self.assertTrue(Secret.objects.filter(pk=keep.pk).exists())

    def test_secret_delete_noop_on_get(self):
        target = make_secret(self.project, self.key, name="GETSAFE", value="v")
        url = reverse(
            "vault:secret_delete",
            kwargs={"public_id": self.project.public_id, "secret_id": target.id},
        )
        self.client.get(url)
        self.assertTrue(Secret.objects.filter(pk=target.pk).exists())


# ---------------------------------------------------------------------------
# Web view: API key mint / revoke lifecycle (+ REST cross-check)
# ---------------------------------------------------------------------------

class VaultWebAPIKeyTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", password="pw")
        self.project, self.key = make_project(self.owner)
        make_secret(self.project, self.key)
        verified_login(self.client, self.owner)
        self.create_url = reverse(
            "vault:api_key_create", kwargs={"public_id": self.project.public_id}
        )

    def test_api_key_create_mints_and_stores_once(self):
        res = self.client.post(self.create_url)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(ProjectAPIKey.objects.filter(project=self.project).exists())
        raw = self.client.session.get(NEW_API_KEY_SESSION)
        self.assertTrue(raw.startswith("dhk_"))
        # one-time display: popped on next detail render
        detail = self.client.get(
            reverse("vault:detail", kwargs={"public_id": self.project.public_id})
        )
        self.assertEqual(detail.context["new_api_key"], raw)
        self.assertIsNone(self.client.session.get(NEW_API_KEY_SESSION))

    def test_minted_key_authenticates_rest_then_revoke_blocks(self):
        self.client.post(self.create_url)
        raw = self.client.session.get(NEW_API_KEY_SESSION)
        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.assertEqual(api.get("/api/secrets").status_code, 200)

        key_obj = ProjectAPIKey.objects.filter(project=self.project).latest("id")
        revoke_url = reverse(
            "vault:api_key_revoke",
            kwargs={"public_id": self.project.public_id, "key_id": key_obj.id},
        )
        self.client.post(revoke_url)
        self.assertEqual(api.get("/api/secrets").status_code, 401)

    def test_api_key_revoke_cross_tenant_404(self):
        attacker = User.objects.create_user(username="attacker", password="pw")
        atk = self.client_class()
        verified_login(atk, attacker)
        key_obj, _ = ProjectAPIKey.generate(self.project)
        revoke_url = reverse(
            "vault:api_key_revoke",
            kwargs={"public_id": self.project.public_id, "key_id": key_obj.id},
        )
        res = atk.post(revoke_url)
        self.assertEqual(res.status_code, 404)
        key_obj.refresh_from_db()
        self.assertTrue(key_obj.is_active())

    def test_api_key_create_noop_on_get(self):
        before = ProjectAPIKey.objects.filter(project=self.project).count()
        self.client.get(self.create_url)
        self.assertEqual(ProjectAPIKey.objects.filter(project=self.project).count(), before)

    def test_api_key_revoke_noop_on_get(self):
        key_obj, _ = ProjectAPIKey.generate(self.project)
        url = reverse(
            "vault:api_key_revoke",
            kwargs={"public_id": self.project.public_id, "key_id": key_obj.id},
        )
        self.client.get(url)
        key_obj.refresh_from_db()
        self.assertTrue(key_obj.is_active())


# ---------------------------------------------------------------------------
# REST endpoint: scoping & auth failure modes
# ---------------------------------------------------------------------------

class VaultRestAuthTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", password="pw")
        self.project_a, self.key_a = make_project(self.owner, name="proj-a")
        self.project_b, self.key_b = make_project(self.owner, name="proj-b")
        make_secret(self.project_a, self.key_a, name="a-secret", value="aaa")
        make_secret(self.project_b, self.key_b, name="b-secret", value="bbb")
        self.api_key_a, self.token_a = ProjectAPIKey.generate(self.project_a)
        self.client = APIClient()

    def test_key_scoped_to_its_own_project(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        res = self.client.get("/api/secrets")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["keys"], ["a-secret"])
        # cannot reach project B's secret with A's key
        self.assertEqual(self.client.get("/api/secrets/b-secret").status_code, 404)
        self.assertEqual(self.client.get("/api/secrets/a-secret").status_code, 200)

    def test_malformed_and_wrong_prefix_headers_rejected(self):
        for header in ("Token abc", "Bearer", "Bearer not_a_dhk_token", f"Bearer dh_live_{'x'*10}"):
            self.client.credentials(HTTP_AUTHORIZATION=header)
            res = self.client.get("/api/secrets")
            self.assertEqual(res.status_code, 401, msg=header)

    def test_missing_header_rejected(self):
        self.client.credentials()
        self.assertEqual(self.client.get("/api/secrets").status_code, 401)

    def test_expired_key_rejected(self):
        self.api_key_a.expires_at = timezone.now() - timedelta(days=1)
        self.api_key_a.save(update_fields=["expires_at"])
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token_a}")
        self.assertEqual(self.client.get("/api/secrets").status_code, 401)
