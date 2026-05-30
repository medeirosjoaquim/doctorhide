from .models import AuditEvent, Project, ProjectAPIKey


def client_ip(request):
    """Best-effort client IP from a request, honouring a forwarding proxy."""
    if request is None:
        return None
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _resolved_auth(request):
    """The ProjectAPIKey already attached to the request, if any.

    Reads the cached ``_auth`` set by DRF after authentication; never touches
    the lazy ``request.auth`` property, which would re-trigger authentication
    (and recurse when called from inside an authenticator).
    """
    auth = getattr(request, "_auth", None)
    return auth if isinstance(auth, ProjectAPIKey) else None


def _resolved_project(request):
    """The Project already attached to the request, if any (cached only)."""
    user = getattr(request, "_user", None)
    return user if isinstance(user, Project) else None


def record(request, action, outcome, project=None, secret_key="", principal=None):
    """Write an append-only audit event.

    ``project`` defaults to the authenticated project on the request when not
    given explicitly. ``principal`` may be passed when the request is not yet
    authenticated (e.g. during key auth). ``request`` may be ``None``.
    """
    if request is not None:
        if project is None:
            project = _resolved_project(request)
        if principal is None:
            auth = _resolved_auth(request)
            if auth is not None:
                principal = auth.prefix
    return AuditEvent.objects.create(
        principal=principal or "",
        action=action,
        outcome=outcome,
        project=project,
        secret_key=secret_key or "",
        source_ip=client_ip(request),
    )
