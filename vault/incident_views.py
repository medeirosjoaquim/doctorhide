"""Admin-only incident-response endpoints.

The single endpoint here is the operator-side counterpart to the
``emergency_revoke_all_keys`` management command: same blast radius, same
audit trail, exposed over HTTPS so an on-call responder does not need shell
access to the application server. The constraints are deliberately strict
(superuser + TOTP + tight throttle + audit log) because a stray call here
disables every API key in an organization.
"""

from __future__ import annotations

from datetime import UTC, datetime

from django.db import transaction
from django.utils import timezone as dj_timezone
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from organizations.models import Organization

from .models import AuditEvent, ProjectAPIKey
from .throttling import IncidentRateThrottle


def _parse_when(value):
    """Parse an optional ISO-8601 ``before`` cutoff. Accepts a leading ``Z``
    suffix and naïve strings (treated as UTC). Returns ``None`` when omitted."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _audit(request, action, outcome, *, organization=None, secret_key=""):
    """Write an audit row for an incident call. Mirrors ``vault.audit.record``
    but records the acting user as the principal and supports organization
    scoping, which the generic helper does not (yet)."""
    principal = ""
    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        principal = f"superuser:{user.get_username()}"
    return AuditEvent.objects.create(
        principal=principal,
        action=action,
        outcome=outcome,
        organization=organization,
        secret_key=secret_key,
        source_ip=None,
    )


@api_view(["POST"])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([IncidentRateThrottle])
def incident_revoke_all_keys(request):
    """``POST /admin/incident/revoke-all-keys`` — revoke every still-active
    ProjectAPIKey in a target organization, optionally limited to keys
    created before a cutoff.

    Body (JSON, all optional except by convention)::

        {"org": <organization_id>, "before": "<iso-8601>"}

    The endpoint requires:
      * an authenticated session,
      * ``request.user.is_superuser`` (only superusers may invoke it),
      * ``request.user.is_verified()`` (the django-otp flag; enforces TOTP),
      * the per-user IncidentRateThrottle to be under its limit.

    Every call — successful, denied, throttled — is recorded in
    AuditEvent with action ``incident.revoke_all_keys`` and an outcome
    that captures the result so the legal record is complete.
    """
    user = request.user

    # Auth gates. We log each denial as its own audit row so the response
    # trail is faithful: "X tried, was denied because Y" must be queryable.
    if not getattr(user, "is_superuser", False):
        _audit(request, "incident.revoke_all_keys", "denied:not_superuser")
        return Response(
            {"detail": "Superuser privileges required."},
            status=status.HTTP_403_FORBIDDEN,
        )
    if not getattr(user, "is_verified", lambda: False)():
        _audit(request, "incident.revoke_all_keys", "denied:totp_required")
        return Response(
            {"detail": "TOTP verification required."},
            status=status.HTTP_403_FORBIDDEN,
        )

    # Body parsing. Accept both JSON and form-encoded for ease of use from
    # a curl one-liner in the heat of an incident.
    payload = request.data if hasattr(request, "data") else {}
    org_id = payload.get("org")
    if org_id is None:
        _audit(request, "incident.revoke_all_keys", "denied:missing_org")
        return Response(
            {"detail": "`org` is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        org_id = int(org_id)
    except (TypeError, ValueError):
        _audit(request, "incident.revoke_all_keys", "denied:invalid_org")
        return Response(
            {"detail": "`org` must be an integer organization id."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    organization = Organization.objects.filter(pk=org_id).first()
    if organization is None:
        _audit(request, "incident.revoke_all_keys", "denied:unknown_org")
        return Response(
            {"detail": f"No organization with id={org_id}."},
            status=status.HTTP_404_NOT_FOUND,
        )

    before = _parse_when(payload.get("before"))
    if payload.get("before") not in (None, "") and before is None:
        _audit(
            request,
            "incident.revoke_all_keys",
            "denied:invalid_before",
            organization=organization,
        )
        return Response(
            {"detail": "`before` is not a valid ISO-8601 timestamp."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    qs = ProjectAPIKey.objects.filter(
        project__organization_id=org_id,
        revoked_at__isnull=True,
    )
    if before is not None:
        qs = qs.filter(created_at__lt=before)

    target_ids = qs.values_list("pk", flat=True)
    with transaction.atomic():
        revoked = (
            ProjectAPIKey.objects.filter(pk__in=target_ids)
            .update(revoked_at=dj_timezone.now())
        )
        _audit(
            request,
            "incident.revoke_all_keys",
            "success",
            organization=organization,
            secret_key=f"revoked={revoked}" + (
                f";before={before.isoformat()}" if before is not None else ""
            ),
        )

    return Response(
        {
            "revoked": revoked,
            "org": org_id,
            "before": before.isoformat() if before is not None else None,
        },
        status=status.HTTP_200_OK,
    )
