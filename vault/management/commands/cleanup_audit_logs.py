"""Purge AuditEvent rows older than the retention window.

The Week 6 retention policy is 90 days. Schedule this command weekly
from cron / k8s CronJob:

    python manage.py cleanup_audit_logs            # default 90 days
    python manage.py cleanup_audit_logs --days=30  # tighter window

Compliance footnote: SOC 2 Type II asks for a documented retention
window with a real purge process (not "logically deleted" rows that
stay in the table forever). The ``--days`` flag is exposed so an
auditor can verify the actual configured value without reading code;
the operator-facing runbook (``RUNBOOK.md``) documents the schedule.

The command is idempotent: running it twice in a row is a no-op the
second time. It prints a summary line at the end so the cron job's
log shows what was deleted.
"""

from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from vault.models import AuditEvent

DEFAULT_RETENTION_DAYS = 90


class Command(BaseCommand):
    help = (
        "Delete AuditEvent rows older than the retention window. "
        f"Default: {DEFAULT_RETENTION_DAYS} days. Idempotent."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=DEFAULT_RETENTION_DAYS,
            help=(
                f"Retention window in days. Rows with timestamp older than "
                f"(now - days) are deleted. Default: {DEFAULT_RETENTION_DAYS}."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Count the rows that would be deleted, but don't delete anything.",
        )

    def handle(self, *args, **options):
        days = options["days"]
        dry_run = options["dry_run"]
        if days < 0:
            self.stderr.write("--days must be >= 0")
            return

        cutoff = timezone.now() - timedelta(days=days)
        # The delete is wrapped in a transaction so a partial failure
        # doesn't leave the table half-purged. The AuditEvent table can
        # be large in production, but ``timestamp__lt`` is indexed
        # (db_index=True on the model) so the WHERE clause is cheap.
        queryset = AuditEvent.objects.filter(timestamp__lt=cutoff)
        count = queryset.count()
        if dry_run:
            self.stdout.write(
                f"[DRY-RUN] Would delete {count} AuditEvent row(s) with "
                f"timestamp < {cutoff.isoformat()}."
            )
            return

        with transaction.atomic():
            deleted, _ = queryset.delete()
        self.stdout.write(
            f"Deleted {deleted} AuditEvent row(s) with timestamp < "
            f"{cutoff.isoformat()}."
        )
