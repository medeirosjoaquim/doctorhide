"""Hard-delete ``Secret`` rows past the 30-day recovery window.

The soft-delete flow (Week 1+) keeps a deleted secret recoverable
in the UI for 30 days. After 30 days the ciphertext and version
rows are gone for good: this command is the irreversible half of
the delete lifecycle.

The model declares ``Secret.RECOVERY_WINDOW = 30 days``. This
command reads the same constant (no hard-coded value), so the policy
is in one place. A change to the model's window takes effect on
the next cron run with no code change here.

Schedule weekly from cron / k8s CronJob:

    python manage.py cleanup_deleted_secrets             # default 30 days
    python manage.py cleanup_deleted_secrets --days=7    # tighter window

The command is idempotent and prints a summary line so the cron log
shows the delete count. ``--dry-run`` is supported.
"""

from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from vault.models import Secret


class Command(BaseCommand):
    help = (
        "Hard-delete Secret rows whose soft-delete grace period has "
        "expired (default: 30 days past deleted_at). Idempotent."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=Secret.RECOVERY_WINDOW.days,
            help=(
                "Recovery window in days. Rows with deleted_at older than "
                "(now - days) are hard-deleted. Default matches the model: "
                f"{Secret.RECOVERY_WINDOW.days}."
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
        queryset = Secret.objects.filter(deleted_at__lt=cutoff)
        count = queryset.count()
        if dry_run:
            self.stdout.write(
                f"[DRY-RUN] Would hard-delete {count} Secret row(s) with "
                f"deleted_at < {cutoff.isoformat()}. "
                f"(Cascades to SecretVersion rows.)"
            )
            return

        with transaction.atomic():
            deleted, _ = queryset.delete()
        self.stdout.write(
            f"Hard-deleted {deleted} Secret row(s) with deleted_at < "
            f"{cutoff.isoformat()} (cascades to SecretVersion rows)."
        )
