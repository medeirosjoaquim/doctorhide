"""Custom DRF exception handler that audits throttled calls to the
admin incident endpoint.

DRF raises ``exceptions.Throttled`` *before* the view body runs, so a
rate-limited caller never reaches the per-view ``_audit()`` helper that
writes the success/denial rows for the incident endpoint. Without this
handler, a tight throttle loop would silently drop every rejected call
from the audit trail — a hole in exactly the part of the audit log an
on-call investigator will reach for first ("who hammered the kill switch
and got 429s?").

The handler runs for every DRF view; we narrow it to the incident view
by name so a noisy throttled call on, say, ``/api/secrets`` does not
flood the audit table.
"""

from __future__ import annotations

import logging

from rest_framework import exceptions
from rest_framework.views import exception_handler as drf_default_exception_handler

from .models import AuditEvent

logger = logging.getLogger(__name__)

# Identified by the URL name set in ``doctorhide/urls.py`` rather than the
# function name, because ``@api_view`` wraps the function in a class and the
# resulting ``view`` object's ``__name__`` is the wrapping view's ``view``,
# not the underlying function. ``request.resolver_match.url_name`` survives
# that wrapping.
INCIDENT_URL_NAMES = {"incident_revoke_all_keys"}


def _is_incident_request(request) -> bool:
    match = getattr(request, "resolver_match", None)
    if match is None:
        return False
    return match.url_name in INCIDENT_URL_NAMES


def _safe_request_data(request):
    """Best-effort parse the request body so the audit row can name the org.

    DRF's throttle fires before the view body parses the body, so when the
    throttle trips we have to read it here. ``request.data`` is lazy, so
    calling it for the first time in the handler parses the body; for
    throttled calls the body has already been received by the WSGI layer
    and is sitting in ``request.body`` / ``request.data``.

    Returns an empty dict on any parse error rather than letting the
    exception escape the handler (which would 500 the request and lose
    the audit row we are trying to write).
    """
    try:
        return dict(request.data) if request.data else {}
    except Exception:
        return {}


def _principal(request):
    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        return f"superuser:{user.get_username()}"
    return "anonymous"


def incident_exception_handler(exc, context):
    """Write an audit row for a throttled call to the incident endpoint, then
    defer to the default DRF handler to produce the standard 429 response.

    The default handler returns ``Response(status=429, headers={...})`` when
    given a ``Throttled`` exception; we return that response unchanged after
    side-effecting the audit write.
    """
    request = context.get("request")

    if (
        isinstance(exc, exceptions.Throttled)
        and request is not None
        and _is_incident_request(request)
    ):
        payload = _safe_request_data(request)
        org_id = None
        raw_org = payload.get("org")
        if raw_org is not None:
            try:
                org_id = int(raw_org)
            except (TypeError, ValueError):
                org_id = None

        try:
            AuditEvent.objects.create(
                principal=_principal(request),
                action="incident.revoke_all_keys",
                outcome="denied:throttled",
                organization_id=org_id,
                secret_key=(
                    f"wait={exc.wait}" if getattr(exc, "wait", None) is not None else ""
                ),
            )
        except Exception:
            # Never let an audit write failure 500 a throttled response.
            # The throttle itself still trips; we just lose the row. Log
            # the failure for the operator to investigate later.
            logger.exception(
                "Failed to write throttled-call audit row for url_name=%s",
                getattr(getattr(request, "resolver_match", None), "url_name", None),
            )

    return drf_default_exception_handler(exc, context)

