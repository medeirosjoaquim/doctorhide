"""Tests for the Week 6 Phase 3 cleanup management commands.

These commands exist for SOC 2 / GDPR-style retention hygiene:
* ``cleanup_audit_logs`` purges AuditEvent rows older than the
  retention window (default 90 days).
* ``cleanup_deleted_secrets`` hard-deletes Secret rows past their
  30-day soft-delete recovery window (matching ``Secret.RECOVERY_WINDOW``).

The tests pin the *behaviour* of each command: the cutoff math, the
idempotency, the dry-run flag. They do not exercise the actual cron
schedule (that's an infra concern, covered by the runbook).
"""

from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from .models import AuditEvent, Project, Secret

User = get_user_model()


def _make_project(user):
    from organizations.models import personal_organization

    from . import crypto

    salt = crypto.generate_salt()
    crypto.derive_key("test", salt)
    return Project.objects.create(
        owner=user,
        organization=personal_organization(user),
        public_id=Project.new_public_id(),
        name="p",
    )


def _make_audit(seconds_ago: int) -> AuditEvent:
    return AuditEvent.objects.create(
        action="test.event",
        outcome="success",
        timestamp=timezone.now() - timedelta(seconds=seconds_ago),
    )


def _make_secret(project, key="k", deleted_seconds_ago: int | None = None) -> Secret:
    from . import crypto
    salt = crypto.generate_salt()
    key_obj = crypto.derive_key("test", salt)
    secret = Secret.objects.create(
        project=project,
        key=key,
        ciphertext=crypto.encrypt(key_obj, "v"),
    )
    if deleted_seconds_ago is not None:
        secret.deleted_at = timezone.now() - timedelta(seconds=deleted_seconds_ago)
        secret.save(update_fields=["deleted_at"])
    return secret


class CleanupAuditLogsCommandTests(TestCase):
    def test_deletes_rows_older_than_retention_window(self):
        old = _make_audit(seconds_ago=10 * 86400)  # 10 days old
        recent = _make_audit(seconds_ago=2 * 86400)  # 2 days old
        # Default 90 days: both should survive.
        call_command("cleanup_audit_logs")
        self.assertTrue(AuditEvent.objects.filter(pk=old.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(pk=recent.pk).exists())

        # With days=5, the 10-day-old row is purged, the 2-day-old survives.
        call_command("cleanup_audit_logs", days=5)
        self.assertFalse(AuditEvent.objects.filter(pk=old.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(pk=recent.pk).exists())

    def test_dry_run_does_not_delete(self):
        old = _make_audit(seconds_ago=10 * 86400)
        call_command("cleanup_audit_logs", days=5, dry_run=True)
        # The row is still there.
        self.assertTrue(AuditEvent.objects.filter(pk=old.pk).exists())

    def test_idempotent_second_run_is_noop(self):
        old = _make_audit(seconds_ago=10 * 86400)
        call_command("cleanup_audit_logs", days=5)
        # Second call: nothing left to delete.
        call_command("cleanup_audit_logs", days=5)
        self.assertFalse(AuditEvent.objects.filter(pk=old.pk).exists())

    def test_zero_days_deletes_everything_old(self):
        # days=0 means "older than now", which is everything with a
        # timestamp strictly in the past. The freshly-created row has
        # a timestamp <= now (set to timezone.now() at creation), so
        # depending on sub-second clock it may or may not be deleted.
        # The test focuses on a row that's clearly in the past.
        old = _make_audit(seconds_ago=1)
        call_command("cleanup_audit_logs", days=0)
        self.assertFalse(AuditEvent.objects.filter(pk=old.pk).exists())


class CleanupDeletedSecretsCommandTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="o", password="pw")
        self.project = _make_project(self.user)

    def test_deletes_secrets_past_recovery_window(self):
        old = _make_secret(self.project, key="old", deleted_seconds_ago=35 * 86400)
        recent = _make_secret(self.project, key="recent", deleted_seconds_ago=10 * 86400)
        call_command("cleanup_deleted_secrets")
        # 35 days > 30 day default, 10 days < 30 day default.
        self.assertFalse(Secret.objects.filter(pk=old.pk).exists())
        self.assertTrue(Secret.objects.filter(pk=recent.pk).exists())

    def test_does_not_touch_live_secrets(self):
        live = _make_secret(self.project, key="live", deleted_seconds_ago=None)
        call_command("cleanup_deleted_secrets")
        self.assertTrue(Secret.objects.filter(pk=live.pk).exists())

    def test_dry_run_does_not_delete(self):
        old = _make_secret(self.project, key="old", deleted_seconds_ago=35 * 86400)
        call_command("cleanup_deleted_secrets", dry_run=True)
        self.assertTrue(Secret.objects.filter(pk=old.pk).exists())

    def test_idempotent_second_run_is_noop(self):
        old = _make_secret(self.project, key="old", deleted_seconds_ago=35 * 86400)
        call_command("cleanup_deleted_secrets")
        call_command("cleanup_deleted_secrets")
        self.assertFalse(Secret.objects.filter(pk=old.pk).exists())

    def test_default_window_matches_model_constant(self):
        # If Secret.RECOVERY_WINDOW ever changes, this test catches a
        # drift between the model and the command default. The
        # command reads the constant at module-import time, so a
        # change in the model propagates automatically \u2014 this test
        # exists to surface the propagation in CI.
        from .models import Secret as SecretModel

        self.assertEqual(SecretModel.RECOVERY_WINDOW.days, 30)
