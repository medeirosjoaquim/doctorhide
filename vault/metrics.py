"""Custom Prometheus counters for the vault.

django-prometheus exports a wealth of auto-instrumented metrics
(request latency, DB query time, model ops, etc.) via ``/metrics``,
but the *security-relevant* signals the Week 6 alerting rules care
about are not in that default set. This module declares them as
prometheus_client Counter objects so the views can ``.labels(...)`` and
``.inc()`` them at the right call sites.

Counter shape
-------------
* All counters are labelled with ``outcome`` (``success`` / ``denied`` /
  ``error``) so the alerting rules can fire on the failure rate, not
  the absolute volume.
* The secret counters also carry ``project_id`` so a single noisy
  project doesn't drown the global alert; the Week 6 alerts run on
  *per-key* rates via PromQL ``sum by (api_key_prefix)`` aggregations.
* ``vault_unlock_failures_total`` is intentionally per-project (not
  per-IP) for now; per-IP tracking is a Week 6 Phase 2 follow-up.

Note on label cardinality
-------------------------
``project_id`` has the same cardinality as the number of projects
(small). ``api_key_prefix`` would have higher cardinality and is
deliberately *not* a label here; per-key breakdowns happen in PromQL
by joining against a separate per-key metric added in a follow-up if
the alert rules need it.
"""

from __future__ import annotations

from prometheus_client import Counter

# Successful secret read (GET /api/secrets/{key} returning 200).
vault_secret_reads_total = Counter(
    "vault_secret_reads_total",
    "Total number of successful secret reads via the API.",
    ["project_id", "outcome"],
)

# Batch secret reads (POST /api/secrets/batch). The "outcome" label
# tracks whether the batch was served (success) or rejected (e.g. a
# key in the batch didn't exist, which is *not* an error from the
# caller's perspective but is worth distinguishing from a clean
# success).
vault_secret_batch_get_total = Counter(
    "vault_secret_batch_get_total",
    "Total number of batch secret reads via the API.",
    ["project_id", "outcome"],
)

# Failed project unlock (POST /projects/<id>/unlock with a wrong
# passphrase). Distinct from auth_login_failed because the
# unlock endpoint is project-scoped, not user-scoped.
vault_unlock_failures_total = Counter(
    "vault_unlock_failures_total",
    "Total number of failed project unlock attempts (wrong passphrase).",
    ["project_id"],
)

# Security alerts emitted by the in-process detectors (Week 6 Phase 2).
# The ``type`` label matches the alert-rule ``alert`` names so a
# single dashboard panel can group by alert type.
vault_security_alerts_total = Counter(
    "vault_security_alerts_total",
    "Total number of security alerts emitted by in-process detectors.",
    ["type", "severity"],
)
