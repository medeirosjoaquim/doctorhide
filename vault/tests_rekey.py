"""Tests for the forced passphrase rekey flow.

The rekey view is the user-facing counterpart to the
``Project.requires_rekey`` flag. These tests pin the contract:

* a wrong old passphrase leaves the project untouched and emits a
  ``denied:wrong_old_passphrase`` audit row;
* a correct rekey re-encrypts every secret *and* every SecretVersion
  under the new key, rotates salt/verifier, clears the flag, drops the
  unlock key from the current session, and emits a success audit row
  with the rotated counts;
* rekey invalidates the unlock key in any *other* session that had it
  cached;
* the rekey endpoint requires OWNER role on the organization;
* when ``Project.requires_rekey`` is set, ``project_unlock`` redirects
  to the rekey flow instead of granting access.
"""

from __future__ import annotations

from datetime import UTC

from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client, TestCase
from django.urls import reverse
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.plugins.otp_static.models import StaticDevice

from . import crypto
from .models import AuditEvent, Project, Secret, SecretVersion
from .views import SESSION_KEYS

User = get_user_model()

OLD_PASSPHRASE = "old-correct-horse"
NEW_PASSPHRASE = "new-battery-staple-42"


def _verified_login(client, user):
    """Log ``user`` in with an OTP-verified session so ``@otp_required``
    passes. Mirrors ``tests_authz.verified_login``: bind a confirmed
    StaticDevice to the session via the django-otp persistent id.

    NB: the device is created *before* ``force_login``. With the
    opposite order, ``force_login`` resets the session and the
    subsequent session edits are written to a session that the
    middleware no longer recognises.
    """
    device = StaticDevice.objects.create(user=user, name="backup", confirmed=True)
    client.force_login(user)
    session = client.session
    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    return device


class ProjectRekeyViewTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner", password="owner-pw-123"
        )
        self.member = User.objects.create_user(
            username="member", password="member-pw-123"
        )
        from organizations.models import Membership, personal_organization

        self.org = personal_organization(self.owner)
        # Member joins the same org at MEMBER level.
        Membership.objects.create(
            organization=self.org, user=self.member, role=Membership.ROLE_MEMBER
        )

        self.client = Client()
        self.salt = crypto.generate_salt()
        self.old_key = crypto.derive_key(OLD_PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.owner,
            organization=self.org,
            public_id=Project.new_public_id(),
            name="prod",
        )
        env = self.project.default_environment
        env.salt = self.salt
        env.verifier = crypto.make_verifier(self.old_key)
        env.save(update_fields=["salt", "verifier"])
        # Two secrets + a few version rows, so we can prove all of them
        # get re-encrypted.
        self.s1 = Secret.objects.create(
            project=self.project,
            key="DB_PASSWORD",
            ciphertext=crypto.encrypt(self.old_key, "v1"),
        )
        SecretVersion.objects.create(
            secret=self.s1, ciphertext=crypto.encrypt(self.old_key, "v0")
        )
        SecretVersion.objects.create(
            secret=self.s1, ciphertext=crypto.encrypt(self.old_key, "v1")
        )
        self.s2 = Secret.objects.create(
            project=self.project,
            key="API_KEY",
            ciphertext=crypto.encrypt(self.old_key, "k1"),
        )
        SecretVersion.objects.create(
            secret=self.s2, ciphertext=crypto.encrypt(self.old_key, "k0")
        )
        SecretVersion.objects.create(
            secret=self.s2, ciphertext=crypto.encrypt(self.old_key, "k1")
        )

    def _login(self, user):
        _verified_login(self.client, user)

    def _rekey_url(self):
        return reverse("vault:rekey", args=[self.project.public_id])

    # --- happy path ---

    def test_rekey_re_encrypts_secrets_and_versions_under_new_key(self):
        self._login(self.owner)
        old_salt = self.project.salt
        old_verifier = self.project.verifier
        # Owner unlocks with the OLD key first, to make sure rekey drops it.
        self.client.post(
            reverse("vault:unlock", args=[self.project.public_id]),
            {"passphrase": OLD_PASSPHRASE},
        )
        self.assertIsNotNone(
            self.client.session.get(SESSION_KEYS, {}).get(self.project.public_id)
        )

        resp = self.client.post(
            self._rekey_url(),
            {
                "old_passphrase": OLD_PASSPHRASE,
                "new_passphrase": NEW_PASSPHRASE,
                "new_passphrase_confirm": NEW_PASSPHRASE,
            },
        )
        self.assertEqual(resp.status_code, 302, resp.content)
        self.assertEqual(
            resp["Location"], reverse("vault:detail", args=[self.project.public_id])
        )

        # Project salt/verifier/flag rotated.
        self.project.refresh_from_db()
        self.assertNotEqual(self.project.salt, old_salt)
        self.assertNotEqual(self.project.verifier, old_verifier)
        self.assertFalse(self.project.requires_rekey)

        # New key derives from the new passphrase + the new salt and
        # verifies against the new verifier.
        new_key = crypto.derive_key(NEW_PASSPHRASE, self.project.salt)
        self.assertTrue(crypto.verify_key(new_key, self.project.verifier))

        # Every Secret and every SecretVersion decrypts under the new key.
        for secret in (self.s1, self.s2):
            secret.refresh_from_db()
            self.assertEqual(
                crypto.decrypt(new_key, secret.ciphertext),
                {"DB_PASSWORD": "v1", "API_KEY": "k1"}[secret.key],
            )
            for version in secret.versions.all():
                version.refresh_from_db()
                crypto.decrypt(new_key, version.ciphertext)  # must not raise

        # Old key can no longer unlock the project.
        self.assertFalse(
            crypto.verify_key(self.old_key, self.project.verifier)
        )

        # Current session's unlock key has been dropped.
        self.assertNotIn(
            self.project.public_id, self.client.session.get(SESSION_KEYS, {})
        )

        # Audit event captures the counts.
        ev = AuditEvent.objects.get(action="project.rekey", outcome="success")
        self.assertEqual(ev.project, self.project)
        self.assertIn("secrets=2", ev.secret_key)
        self.assertIn("versions=4", ev.secret_key)
        self.assertIn("sessions_invalidated=", ev.secret_key)

    def test_rekey_drops_unlock_key_from_other_sessions(self):
        # Simulate a second device that has already unlocked the project.
        store = SessionStore()
        store[SESSION_KEYS] = {self.project.public_id: "stale-key"}
        store.save()
        stale_session_key = store.session_key
        self.assertIsNotNone(stale_session_key)

        self._login(self.owner)
        self.client.post(
            self._rekey_url(),
            {
                "old_passphrase": OLD_PASSPHRASE,
                "new_passphrase": NEW_PASSPHRASE,
                "new_passphrase_confirm": NEW_PASSPHRASE,
            },
        )

        # The stale session's unlock key for this project is gone.
        reloaded = SessionStore(session_key=stale_session_key)
        self.assertNotIn(
            self.project.public_id, reloaded.get(SESSION_KEYS, {})
        )

    # --- failure paths ---

    def test_wrong_old_passphrase_does_not_modify_project(self):
        self._login(self.owner)
        old_salt = self.project.salt
        old_verifier = self.project.verifier
        old_s1_ct = self.s1.ciphertext
        old_v_count = self.s1.versions.count()

        resp = self.client.post(
            self._rekey_url(),
            {
                "old_passphrase": "definitely-wrong",
                "new_passphrase": NEW_PASSPHRASE,
                "new_passphrase_confirm": NEW_PASSPHRASE,
            },
        )
        self.assertEqual(resp.status_code, 200, resp.content)  # form re-rendered

        self.project.refresh_from_db()
        self.s1.refresh_from_db()
        self.assertEqual(self.project.salt, old_salt)
        self.assertEqual(self.project.verifier, old_verifier)
        self.assertEqual(self.s1.ciphertext, old_s1_ct)
        self.assertEqual(self.s1.versions.count(), old_v_count)

        self.assertTrue(
            AuditEvent.objects.filter(
                action="project.rekey",
                outcome="denied:wrong_old_passphrase",
                project=self.project,
            ).exists()
        )

    def test_mismatched_new_passphrase_is_rejected(self):
        self._login(self.owner)
        old_salt = self.project.salt
        resp = self.client.post(
            self._rekey_url(),
            {
                "old_passphrase": OLD_PASSPHRASE,
                "new_passphrase": NEW_PASSPHRASE,
                "new_passphrase_confirm": "different",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "do not match")
        self.project.refresh_from_db()
        self.assertEqual(self.project.salt, old_salt)

    def test_short_new_passphrase_is_rejected(self):
        self._login(self.owner)
        old_salt = self.project.salt
        resp = self.client.post(
            self._rekey_url(),
            {
                "old_passphrase": OLD_PASSPHRASE,
                "new_passphrase": "short",
                "new_passphrase_confirm": "short",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "at least 8")
        self.project.refresh_from_db()
        self.assertEqual(self.project.salt, old_salt)

    def test_rekey_requires_owner_role(self):
        # Member can view the project, but cannot rekey it.
        self._login(self.member)
        resp = self.client.post(
            self._rekey_url(),
            {
                "old_passphrase": OLD_PASSPHRASE,
                "new_passphrase": NEW_PASSPHRASE,
                "new_passphrase_confirm": NEW_PASSPHRASE,
            },
        )
        self.assertEqual(resp.status_code, 404)  # tenant boundary stays opaque
        self.project.refresh_from_db()
        self.assertEqual(self.project.salt, self.salt)  # unchanged

    # --- coverage gaps: defensive paths in the rekey view ---

    def test_rekey_handles_malformed_session_row(self):
        """A session-store construction that raises (e.g. a future
        pickle format change, a botched DB migration, or a misbehaving
        cache layer) must not break the rekey. ``_forget_project_in_all_sessions``
        wraps the per-row block in ``except Exception`` and skips the
        bad row. Coverage of ``vault/views.py:302-310``.

        Django's stock session backend swallows most data corruption
        silently and returns ``None`` rather than raising, so this
        test simulates the failure by patching the SessionStore
        *constructor* in ``vault.views`` to raise. The test also
        bypasses the test-client's session mechanism (which depends
        on the same SessionStore) by setting the OTP cookie directly
        via a separate authenticated session, then making the rekey
        POST through that.
        """
        from datetime import datetime
        from unittest import mock

        from django.contrib.sessions.models import Session as SessionModel
        from django.test import Client as TestClient
        from django_otp import DEVICE_ID_SESSION_KEY
        from django_otp.plugins.otp_static.models import StaticDevice

        # Set up a separate, fully-authenticated test client so the
        # mock on SessionStore does not break the request lifecycle
        # of the client used to invoke the view.
        device = StaticDevice.objects.create(
            user=self.owner, name="coverage-device", confirmed=True
        )
        bootstrap = TestClient()
        bootstrap.force_login(self.owner)
        bootstrap_session = bootstrap.session
        bootstrap_session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        bootstrap_session.save()
        # Copy the now-OTP-verified cookie onto the test's self.client.
        # Subsequent requests on self.client will carry the cookie that
        # maps to a session row whose ``otp_device_id`` is set, so
        # @otp_required will pass.
        self.client.cookies[bootstrap.cookies["sessionid"].key] = (
            bootstrap.cookies["sessionid"].value
        )

        # The actual marker row that the loop will visit. Its
        # session_data is empty, which makes ``store.get(SESSION_KEYS)``
        # return None; that's the "no key cached" path, not the
        # "SessionStore raised" path. We force the latter by patching
        # the SessionStore constructor.
        marker = SessionModel(
            session_key="rekey-marker",
            session_data="",
            expire_date=datetime(2099, 1, 1, tzinfo=UTC),
        )
        marker.save()
        try:
            with mock.patch(
                "vault.views.SessionStore",
                side_effect=RuntimeError("session backend offline"),
            ):
                resp = self.client.post(
                    self._rekey_url(),
                    {
                        "old_passphrase": OLD_PASSPHRASE,
                        "new_passphrase": NEW_PASSPHRASE,
                        "new_passphrase_confirm": NEW_PASSPHRASE,
                    },
                )
            # The rekey must still succeed; the broken store is
            # skipped, the success audit row is still written.
            self.assertEqual(resp.status_code, 302, resp.content)
            ev = AuditEvent.objects.get(
                action="project.rekey", outcome="success"
            )
            self.assertEqual(ev.project, self.project)
        finally:
            marker.delete()

    def test_rekey_handles_ciphertext_corruption(self):
        """A Secret whose ciphertext was corrupted *after* the project
        was created but *before* the rekey reads it must surface the
        ``failed:ciphertext_corrupt`` audit row and leave the project
        unchanged. Coverage of ``vault/views.py:416-423``.

        The corruption is produced by saving a ciphertext that is not a
        valid Fernet token on the Secret. The rekey's per-secret
        ``crypto.decrypt(old_key, ...)`` raises ``InvalidFernetToken``;
        the outer ``transaction.atomic()`` rolls back all writes; the
        audit row is emitted.
        """
        self._login(self.owner)
        # The setUp already created ``self.s1`` and ``self.s2`` with
        # valid ciphertext. Corrupt one of them to simulate on-disk
        # damage.
        self.s1.ciphertext = "totally-not-a-fernet-token"
        self.s1.save(update_fields=["ciphertext"])
        resp = self.client.post(
            self._rekey_url(),
            {
                "old_passphrase": OLD_PASSPHRASE,
                "new_passphrase": NEW_PASSPHRASE,
                "new_passphrase_confirm": NEW_PASSPHRASE,
            },
        )
        # Re-render the form, not a redirect (the rekey failed).
        self.assertEqual(resp.status_code, 200, resp.content)
        # The "could not re-encrypt" error is on the page.
        self.assertContains(resp, "Could not re-encrypt every secret")
        # The audit row records the failure.
        ev = AuditEvent.objects.get(
            action="project.rekey", outcome="failed:ciphertext_corrupt"
        )
        self.assertEqual(ev.project, self.project)
        # The project's salt is unchanged (transaction rolled back).
        self.project.default_environment.refresh_from_db()
        self.assertEqual(self.project.salt, self.salt)


class ProjectUnlockRequiresRekeyRedirectTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner", password="owner-pw-123"
        )
        from organizations.models import personal_organization

        self.org = personal_organization(self.owner)
        self.client = Client()
        salt = crypto.generate_salt()
        key = crypto.derive_key(OLD_PASSPHRASE, salt)
        self.project = Project.objects.create(
            owner=self.owner,
            organization=self.org,
            public_id=Project.new_public_id(),
            name="quarantined",
        )
        env = self.project.default_environment
        env.requires_rekey = True
        env.salt = salt
        env.verifier = crypto.make_verifier(key)
        env.save(update_fields=["salt", "verifier", "requires_rekey"])
        _verified_login(self.client, self.owner)

    def test_unlock_redirects_to_rekey_when_flag_is_set(self):
        resp = self.client.post(
            reverse("vault:unlock", args=[self.project.public_id]),
            {"passphrase": OLD_PASSPHRASE},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(
            resp["Location"], reverse("vault:rekey", args=[self.project.public_id])
        )
        # The session must NOT have a cached unlock key for this project.
        self.assertNotIn(
            self.project.public_id, self.client.session.get(SESSION_KEYS, {})
        )

    def test_unlock_still_normal_when_flag_is_clear(self):
        # Clear the flag, then the same unlock form should land on detail
        # with the key cached (regression guard for the redirect branch).
        env = self.project.default_environment
        env.requires_rekey = False
        env.save(update_fields=["requires_rekey"])
        resp = self.client.post(
            reverse("vault:unlock", args=[self.project.public_id]),
            {"passphrase": OLD_PASSPHRASE},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(
            resp["Location"], reverse("vault:detail", args=[self.project.public_id])
        )
        self.assertIsNotNone(
            self.client.session.get(SESSION_KEYS, {}).get(self.project.public_id)
        )
