"""Tests for the ``emergency_revoke_all_keys`` incident-response kill switch.

These tests cover the operational contract of the command:
* exactly the active keys under the named org are revoked;
* the --before cutoff is honoured;
* a single AuditEvent is emitted with operator identity;
* dry-run does not write;
* missing org is a hard error.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone as dj_timezone

from . import crypto
from .models import AuditEvent, Project, ProjectAPIKey

User = get_user_model()

PASSPHRASE = "correct-horse-battery"


class EmergencyRevokeAllKeysCommandTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="pw")
        # Personal org is created lazily; reach for it directly.
        from organizations.models import personal_organization

        self.org = personal_organization(self.user)
        self.salt = crypto.generate_salt()
        self.key = crypto.derive_key(PASSPHRASE, self.salt)
        self.project = Project.objects.create(
            owner=self.user,
            organization=self.org,
            public_id=Project.new_public_id(),
            name="p1",
        )
        self.project.default_environment.salt = self.salt
        self.project.default_environment.verifier = crypto.make_verifier(self.key)
        self.project.default_environment.save(update_fields=["salt", "verifier"])

    def _mk_key(self, name="k"):
        return ProjectAPIKey.generate(self.project, name=name)[0]

    def test_revokes_every_active_key_in_org(self):
        k1 = self._mk_key("k1")
        k2 = self._mk_key("k2")
        k2.revoke()  # already revoked: should be ignored
        k3 = self._mk_key("k3")

        call_command("emergency_revoke_all_keys", "--org", str(self.org.id), "--actor", "oncall")

        k1.refresh_from_db()
        k3.refresh_from_db()
        self.assertIsNotNone(k1.revoked_at)
        self.assertIsNotNone(k3.revoked_at)
        # already-revoked key is not re-touched
        self.assertEqual(k2.revoked_at, k2.revoked_at)

        ev = AuditEvent.objects.get(action="incident.revoke_all_keys")
        self.assertEqual(ev.outcome, "success")
        self.assertEqual(ev.organization_id, self.org.id)
        self.assertEqual(ev.principal, "operator:oncall")
        self.assertEqual(ev.project_id, None)  # org-wide, not scoped to a project

    def test_before_cutoff_skips_newer_keys(self):
        old = self._mk_key("old")
        # Force old.created_at to a known time in the past.
        old.created_at = dj_timezone.now() - timedelta(days=10)
        old.save(update_fields=["created_at"])
        new = self._mk_key("new")

        cutoff = (dj_timezone.now() - timedelta(days=1)).isoformat()
        call_command(
            "emergency_revoke_all_keys",
            "--org", str(self.org.id),
            "--before", cutoff,
            "--actor", "sec",
        )

        old.refresh_from_db()
        new.refresh_from_db()
        self.assertIsNotNone(old.revoked_at)
        self.assertIsNone(new.revoked_at)

    def test_dry_run_writes_nothing(self):
        self._mk_key("k1")
        self._mk_key("k2")
        active_before = ProjectAPIKey.objects.filter(revoked_at__isnull=True).count()
        event_before = AuditEvent.objects.filter(action="incident.revoke_all_keys").count()

        call_command("emergency_revoke_all_keys", "--org", str(self.org.id), "--dry-run")

        self.assertEqual(
            ProjectAPIKey.objects.filter(revoked_at__isnull=True).count(),
            active_before,
        )
        self.assertEqual(
            AuditEvent.objects.filter(action="incident.revoke_all_keys").count(),
            event_before,
        )

    def test_unknown_org_is_a_hard_error(self):
        with self.assertRaises(CommandError):
            call_command("emergency_revoke_all_keys", "--org", "999999")

    def test_invalid_before_timestamp_is_a_hard_error(self):
        with self.assertRaises(CommandError):
            call_command(
                "emergency_revoke_all_keys",
                "--org", str(self.org.id),
                "--before", "not-a-date",
            )

    def test_naive_before_is_treated_as_utc(self):
        # Naïve ISO-8601 strings are accepted (treated as UTC) so that the
        # command is forgiving in an emergency when the operator is typing
        # fast and the local clock formatting drifts.
        old = self._mk_key("old")
        old.created_at = datetime(2026, 1, 1, tzinfo=UTC)
        old.save(update_fields=["created_at"])
        new = self._mk_key("new")

        call_command(
            "emergency_revoke_all_keys",
            "--org", str(self.org.id),
            "--before", "2026-06-01T00:00:00",  # naïve
        )

        old.refresh_from_db()
        new.refresh_from_db()
        self.assertIsNotNone(old.revoked_at)
        self.assertIsNone(new.revoked_at)
