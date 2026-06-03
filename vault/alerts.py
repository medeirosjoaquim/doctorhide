"""In-process anomaly detectors feeding the security-alert counter.

The Prometheus alert rules in ``monitoring/alerts.yml`` run over the
counters declared in ``vault/metrics.py``. Two of those rules key on
auto-instrumented behaviour (Django response codes, unlock-failure
counters). A third class of anomaly \u2014 \"the same source IP is failing
login too often, or a new IP just showed up for a key that's been
quiet for a week\" \u2014 needs in-process state (per-IP / per-key tracking)
that Prometheus doesn't have.

This module provides one detector, ``track_failed_login``, that the
``accounts.views`` login path calls on every failed TOTP or password
step. The detector uses the Django cache to count failures per
``(username, source_ip)`` pair and emits both the Prometheus counter
and an ``AuditEvent(action='security.alert')`` row when the threshold
is crossed. The detector is deliberately tiny: the rule lives in
Prometheus, the state lives in cache, the audit row lives in the
``AuditEvent`` table. Three sources of truth, each with a single job.

The threshold is intentionally generous (5 in 15 minutes per pair)
because real password typos happen. A user who fat-fingers their
TOTP 5 times in 15 minutes is having a bad day, not an attack. The
Prometheus alert is the deduplicator: 5 in 15 min is the *first*
warning, and the operator decides whether to escalate.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.core.cache import cache

from .metrics import vault_security_alerts_total

logger = logging.getLogger(__name__)


# Tunable via settings so an operator can tighten or loosen without a
# code change. Default is the alert-rule threshold (5 in 15 min).
FAILED_LOGIN_THRESHOLD = getattr(
    settings, "SECURITY_ALERT_FAILED_LOGIN_THRESHOLD", 5
)
FAILED_LOGIN_WINDOW_SECONDS = getattr(
    settings, "SECURITY_ALERT_FAILED_LOGIN_WINDOW_SECONDS", 15 * 60
)


def _client_ip(request) -> str:
    """Best-effort client IP. Mirrors ``vault.audit.client_ip`` but
    lives here to avoid a circular import."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def _audit_alert(*, alert_type: str, severity: str, message: str, **extra) -> None:
    """Write an AuditEvent row tagged ``security.alert`` and bump the
    Prometheus counter. Failures in either path are logged but never
    raised: the alert path is a side-effect, not a control-flow
    decision."""
    from .models import AuditEvent

    secret_key = " ".join(f"{k}={v}" for k, v in extra.items())
    try:
        AuditEvent.objects.create(
            principal="system:security_alert",
            action="security.alert",
            outcome=alert_type,
            organization_id=None,
            secret_key=f"severity={severity}; {secret_key}; {message}"[:255],
            source_ip=None,
        )
    except Exception:
        logger.exception("Failed to write security.alert audit row")

    try:
        vault_security_alerts_total.labels(
            type=alert_type, severity=severity
        ).inc()
    except Exception:
        logger.exception("Failed to increment vault_security_alerts_total")


def track_failed_login(request, *, username: str, step: str) -> str | None:
    """Increment the per-(username, source_ip) failure counter and
    emit an alert if the threshold is crossed in the window.

    ``step`` is one of ``"password"`` or ``"totp"``; the alert message
    records which step is failing so the operator can distinguish
    brute-force password attacks from TOTP-resync confusion.

    Returns the alert_type that was emitted (so the caller can log it
    or surface a friendly message), or ``None`` if no alert fired.
    """
    ip = _client_ip(request)
    # Per-pair key. A real attack from one IP against one user
    # produces the same key for every attempt; a distributed attempt
    # produces different keys (and each individual IP stays under
    # the threshold). The distributed case is covered by a separate
    # alert rule (failed logins across many IPs in a short window)
    # if/when the project grows.
    cache_key = f"failed_login:{username}:{ip}:{step}"
    try:
        count = cache.get(cache_key, 0) + 1
        cache.set(cache_key, count, FAILED_LOGIN_WINDOW_SECONDS)
    except Exception:
        # Cache outage must not break login, but it also must not
        # silently swallow the counter. The Prometheus counter on
        # the unlock endpoint is the fallback signal.
        logger.exception("Cache failure in track_failed_login; counter lost")
        return None

    if count == FAILED_LOGIN_THRESHOLD:
        alert_type = f"failed_login:{step}"
        _audit_alert(
            alert_type=alert_type,
            severity="high",
            message=(
                f"{count} failed {step} attempts for username={username!r} "
                f"from ip={ip} in the last "
                f"{FAILED_LOGIN_WINDOW_SECONDS // 60} minutes"
            ),
            username=username,
            source_ip=ip,
            count=count,
        )
        return alert_type
    return None
