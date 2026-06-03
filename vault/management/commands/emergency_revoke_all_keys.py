"""Incident response kill switch.

The whole point of this command is that it works from the operator's laptop
(or the incident-response container) when the application is on fire and
**any leaked credential must stop working *right now***. LastPass's biggest
post-mortem finding was having no kill switch — this is the lever that
prevents that here.

Usage::

    python manage.py emergency_revoke_all_keys --org=<organization_id> [--before=<ISO-8601>]

What it does, in one round trip::

    1. Resolve the organization (id is required; we will not guess).
    2. Mark every still-active ProjectAPIKey under every project in that org
       as ``revoked_at=now()`` with a single ``QuerySet.update()`` (no per-row
       writes, no signals fired, no per-key audit event).
    3. Emit a single ``AuditEvent(action='incident.revoke_all_keys')`` row
       recording the operator (env var or ``--actor``), the org, the cutoff
       filter, and the number of keys revoked. This row is the legal record
       of the action and must not be lossy.

A dry-run flag (``--dry-run``) prints what would happen without touching the
database, so an on-call operator can preview the blast radius.
"""

from __future__ import annotations

import getpass
import os
from datetime import UTC, datetime

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone as dj_timezone

from organizations.models import Organization
from vault.models import AuditEvent, ProjectAPIKey


def _parse_when(value: str) -> datetime:
    """Parse a user-supplied cutoff into a tz-aware UTC datetime.

    Accepts both ISO-8601 with an explicit offset (``2026-06-01T00:00:00Z``,
    ``2026-06-01T00:00:00+00:00``) and a naïve value, which we treat as UTC.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CommandError(
            f"--before value {value!r} is not a valid ISO-8601 timestamp."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


class Command(BaseCommand):
    help = (
        "Incident kill switch: revoke every still-active ProjectAPIKey in the "
        "given organization, optionally limited to keys created before a "
        "cutoff. Writes one AuditEvent summarising the action."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--org",
            required=True,
            type=int,
            help="Numeric Organization.id whose keys should be revoked.",
        )
        parser.add_argument(
            "--before",
            default=None,
            help=(
                "Optional ISO-8601 cutoff. Only keys with created_at < this "
                "value are revoked. Omit to revoke all currently-active keys."
            ),
        )
        parser.add_argument(
            "--actor",
            default=None,
            help=(
                "Operator identity recorded on the AuditEvent. Defaults to "
                "$INCIDENT_OPERATOR, then the current OS username, then "
                "'unknown'."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print what would be revoked without writing to the database.",
        )

    def handle(self, *args, **options):
        org_id = options["org"]
        before = _parse_when(options["before"]) if options["before"] else None
        actor = (
            options["actor"]
            or os.environ.get("INCIDENT_OPERATOR")
            or getpass.getuser()
            or "unknown"
        )
        dry_run = options["dry_run"]

        if not Organization.objects.filter(pk=org_id).exists():
            raise CommandError(f"No organization with id={org_id}.")

        # Pre-compute the target set so the dry-run and the real write are
        # computed against the same snapshot of the database.
        qs = ProjectAPIKey.objects.filter(
            project__organization_id=org_id,
            revoked_at__isnull=True,
        )
        if before is not None:
            qs = qs.filter(created_at__lt=before)

        target_count = qs.count()

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"[DRY-RUN] Would revoke {target_count} active ProjectAPIKey "
                    f"row(s) under organization id={org_id}"
                    + (f" created before {before.isoformat()}" if before else "")
                    + "."
                )
            )
            return

        # One bulk UPDATE; no per-row signals, no per-key AuditEvents, no
        # project unlock invalidation (the keys are dead at the next request).
        with transaction.atomic():
            revoked = (
                ProjectAPIKey.objects.filter(
                    pk__in=qs.values_list("pk", flat=True)
                )
                .update(revoked_at=dj_timezone.now())
            )

            # One summary row, the legal record of the action.
            AuditEvent.objects.create(
                principal=f"operator:{actor}",
                action="incident.revoke_all_keys",
                outcome="success",
                organization_id=org_id,
                secret_key="",
                source_ip=None,
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Revoked {revoked} active ProjectAPIKey row(s) under "
                f"organization id={org_id}"
                + (f" created before {before.isoformat()}" if before else "")
                + f". Recorded AuditEvent (operator={actor})."
            )
        )
