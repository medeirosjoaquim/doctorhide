# Incident Response Playbook

This is the operator playbook for responding to a security incident at
doctorhide. It is intentionally focused on the **first hour**: detection,
containment, communication, and the kill switches that exist in the
codebase (Week 1 of the Security Hardening Roadmap). Long-form post-mortem
process and infrastructure-level runbooks live in `RUNBOOK.md`.

> **Drill this.** Reading this document for the first time during a
> real incident is a process failure. Every on-call engineer should
> have run a tabletop exercise against this playbook at least once in
> the last 90 days.

## 1. Roles and contact tree

| Role | Owner | Backup | Paging |
| --- | --- | --- | --- |
| Incident Commander (IC) | on-call engineering lead | secondary on-call | first page |
| Security Lead | security on-call | CISO | first page |
| Comms Lead | product / support lead | CISO | within 30 min of confirmation |
| Database / infra | platform on-call | SRE on-call | as needed |
| Legal | CISO | outside counsel | only if customer data is in scope |

> **Escalate to legal in the first 30 minutes if** any of the following is
> true: a customer secret was returned to an unauthorized party, plaintext
> data was exfiltrated, or a regulator is already asking questions.

## 2. Detection — what should page someone

The signals below should be wired to paging (not just dashboards):

- **Prometheus alert** — see `monitoring/alerts.yml` for the four
  rules that page on-call. The Grafana dashboard
  (`monitoring/grafana/dashboards/doctorhide-overview.json`) shows
  the same counters in graph form for manual investigation. The
  alert rules are:
  - `DoctorhideIncidentEndpointAbuse` — the kill switch is being
    hammered (>5 403/429 in 15 min). Either an attacker probing
    the endpoint or a misconfigured tool.
  - `DoctorhideFailedUnlockSpike` — >5 failed project unlocks in
    15 min on a single project. Likely a passphrase-spray.
  - `DoctorhideSecretReadAnomaly` — >50 secret reads/min on a
    single project for 5 min. Likely a leaked `dhk_` key or an
    exfil script.
  - `DoctorhideSecurityAlertFired` — the in-process detectors
    (`vault.alerts.track_failed_login`) fired. Always
    human-investigate; this is the highest-priority signal.
- **Audit anomaly** — `vault.AuditEvent` shows `key.auth outcome=denied`
  spike (>20/minute from one source IP) or repeated `secret.read` from
  a key that has never been seen before. The Prometheus counters
  (`vault_secret_reads_total`, `vault_unlock_failures_total`,
  `vault_security_alerts_total`) are the same data, queryable in
  PromQL.
- **Application error spike** — `500`-rate on `/api/secrets/*` climbs
  above the 30-day baseline by 3×, or Sentry shows a new error class.
- **Operator alert** — a customer reports a leaked key, a phishing
  campaign against a staff account, or a security researcher contacts
  `security@doctorhide.com`.
- **Host signal** — unusual outbound traffic from an app instance, or
  IAM credential access from a new region.

The first responder triages the signal within 15 minutes, classifies it
as **Confirmed / Likely / Benign** in the incident channel, and pages
the IC.

## 3. Triage checklist (first 15 minutes)

Copy this into the incident channel and tick each box as it is answered.

```
[ ] Open the Grafana "Vault access" dashboard and screenshot the anomaly.
[ ] Query vault.AuditEvent for the affected org / project / API key prefix.
    python manage.py shell -c "
    from vault.models import AuditEvent
    for e in AuditEvent.objects.filter(
        organization_id=<ORG_ID>, timestamp__gte=since
    ).order_by('timestamp'):
        print(e.timestamp, e.action, e.outcome, e.principal, e.source_ip)
    "
[ ] Identify the API key prefix(es) involved (e.g. `dhk_abc12345`).
[ ] Determine the earliest timestamp of suspicious activity.
[ ] Snapshot the affected project's current state (ciphertext, key count,
    recent version writes) so it can be compared against the post-recovery
    state.
[ ] Decide: confirmed breach (continue to step 4) or false positive
    (close the ticket, write a brief note in the channel).
```

## 4. Containment — kill switch

The single most important step is to **stop the bleeding before
investigation**. doctorhide has two parallel kill switches for API
keys; pick whichever is reachable from where you are.

### 4a. CLI kill switch (preferred when you have shell on the app server)

```bash
# Revoke every active ProjectAPIKey under the affected organization.
python manage.py emergency_revoke_all_keys --org=<ORG_ID> --actor=$USER

# Narrower: only revoke keys created before the suspected compromise.
python manage.py emergency_revoke_all_keys \
    --org=<ORG_ID> \
    --before=2026-06-01T00:00:00Z \
    --actor=$USER

# Preview the blast radius without writing.
python manage.py emergency_revoke_all_keys --org=<ORG_ID> --dry-run
```

The command is atomic: one `QuerySet.update()` sets `revoked_at=now()`
on every still-active key in the org, then writes a single
`AuditEvent(action='incident.revoke_all_keys', outcome='success')` row
with `principal=operator:<actor>` for the legal record. Failure modes
are explicit: unknown org → `CommandError`, bad `--before` →
`CommandError`, dry-run → no writes at all.

The redaction is intentionally scoped to a single organization. Do not
run it org-wide; if a system-level breach is suspected, page the
Security Lead and use the API endpoint below for finer control.

### 4b. Admin API endpoint (when you only have HTTPS access)

`POST /admin/incident/revoke-all-keys` — same effect as the CLI, behind
HTTP. The endpoint is gated on **superuser session + TOTP verification**,
and rate-limited at 3 calls/hour per superuser via DRF's
`IncidentRateThrottle`. Every call (success or denial) is recorded in
`AuditEvent`.

```bash
# 1) Authenticate to the admin in a real browser and complete TOTP.
# 2) Capture the session cookie + CSRF token from that browser.
# 3) Issue the kill switch:
curl -sS -X POST https://doctorhide.example.com/admin/incident/revoke-all-keys \
     -H "Content-Type: application/json" \
     -H "X-CSRFToken: $CSRF" \
     -H "Cookie: sessionid=$COOKIE" \
     -d '{"org": 42, "before": "2026-06-01T00:00:00Z"}'
# -> {"revoked": 17, "org": 42, "before": "2026-06-01T00:00:00+00:00"}
```

If you do not have a TOTP-verified superuser session available, do not
fall back to a non-2FA session — page the on-call IC instead, who can
shell onto the app server and use the CLI.

### 4c. Force a passphrase rekey for affected projects

If a user's project passphrase is suspected compromised, setting
`Project.requires_rekey=True` will block normal unlock and force the
user through the rekey flow the next time they try to access the
project. The project itself decides the rotation; the admin path is:

```python
python manage.py shell -c "
from vault.models import Project
Project.objects.filter(public_id='proj_...').update(requires_rekey=True)
"
```

When the affected user next visits the project, they are redirected to
`/projects/<id>/rekey`, which asks for the **current** passphrase (to
prove they can still decrypt) and a **new** one. On success every
`Secret.ciphertext` and every `SecretVersion.ciphertext` is
re-encrypted under the new key in a single transaction, and the
unlock key is dropped from every session row (so a stale browser
session cannot read re-encrypted ciphertexts with the obsolete key).

## 5. Eradication and recovery

1. **Identify the root cause.** Look at the audit log in chronological
   order; the first `outcome=success` event that "should not have
   happened" is usually the entry point. Common patterns:
   - Stolen user password + missing TOTP enforcement → roll the user's
     password and require TOTP re-enrollment.
   - Stolen API key with no expiry → roll forward to a new key with
     a 30-day `expires_at` and add a CI lint to fail unbounded keys.
   - Compromised operator workstation → rotate `SECRET_KEY`, the
     Postgres password, and any KMS keys per `RUNBOOK.md` §SECRET_KEY
     Rotation.
2. **Patch the contributing factor** before restoring service. A
   rekey without patching the cause is a deferral, not a fix.
3. **Restore from backup only if the database is corrupted.** The
   zero-knowledge design means we cannot decrypt ciphertexts without
   the per-project salt + verifier; a restore loses any in-flight
   rekeys. Prefer the in-place rekey above when at all possible.
4. **Re-enable throttles / alerts** that were widened during
   containment.

## 6. User notification template

Send within 24 hours of confirmation, or sooner if any customer data
was returned to an unauthorized party. Adapt the bracketed fields; do
not deviate from the structure without legal review.

> **Subject:** Security incident at doctorhide — action required
>
> Hi {customer_name},
>
> We are writing to inform you of a security incident at doctorhide
> that may have affected your account. **On {detection_date} we
> detected {short_description}, and we have contained the incident.**
>
> **What happened**
> {factual, non-technical description of the incident. Include the
> earliest known date of unauthorized access and the categories of
> data involved.}
>
> **What information was involved**
> {Be specific. "API key prefixes dhk_abc* were revoked" is good.
> Vague language ("some user data may have been accessed") is not.}
>
> **What we have done**
> - Revoked all active API keys in your organization at {timestamp} UTC.
>   You will need to mint new keys and update your service
>   configuration. See {docs_link}.
> - Forced a passphrase rotation on the affected project(s). You will
>   be prompted to set a new passphrase on next login.
> - {Other concrete steps.}
>
> **What you should do**
> 1. {Action 1, with link.}
> 2. {Action 2, with link.}
> 3. {Action 3, with link.}
>
> **Who to contact**
> Reply to this email, or reach our security team at
> security@doctorhide.com. We will respond within one business day.
>
> We sincerely apologize for the inconvenience. We are committed to
> earning back your trust.
>
> {security_lead_name}
> {security_lead_title}, doctorhide

## 7. Post-mortem template

File within 5 business days of incident closure. The template is
deliberately blameless: the goal is to learn, not to assign fault.

```markdown
# Post-mortem: {short title}

- **Incident ID:** {link to ticket}
- **Detection date (UTC):** {ISO-8601}
- **Containment date (UTC):** {ISO-8601}
- **Closure date (UTC):** {ISO-8601}
- **Severity:** {SEV1 / SEV2 / SEV3}
- **IC:** {name}
- **Comms lead:** {name}

## Summary

{One paragraph: what happened, who was affected, what the impact was.}

## Timeline (UTC, +N minutes from detection)

- T+0  — {first signal, e.g. "PagerDuty: AuditEvent anomaly"}
- T+5  — {IC paged}
- T+15 — {containment decision}
- T+30 — {kill switch executed, with command/API call}
- T+45 — {user notification sent}
- ...

## Root cause

{Technical description, with the specific code path, config, or
process that failed. Include the first successful unauthorized event
and the first failure that was missed.}

## Contributing factors

- {e.g. "throttle was disabled for load testing and not re-enabled"}
- {e.g. "no alert on the new AuditEvent action"}

## What went well

- {Detection worked because ...}
- {Kill switch was reachable and well-documented because ...}

## What went poorly

- {On-call did not know the CLI command because ...}
- {Pager was not wired to the right signal because ...}

## Action items

| # | Action | Owner | Due |
| - | --- | --- | --- |
| 1 | {Action, with a one-line rationale} | {name} | {date} |
| 2 | {Action} | {name} | {date} |

## Detection & response metrics

- Time to detect (TTD): {N minutes}
- Time to contain (TTC): {N minutes}
- Time to notify (TTN): {N hours}
- Number of customers notified: {N}
```

## 8. Test the playbook

The playbook is a living document. Run a tabletop exercise quarterly:

1. Pick a scenario from §2 (Detection).
2. Walk the IC through §3–§7 against a staging environment with
   seeded data.
3. Time each phase. If any phase takes more than 30 minutes in
   tabletop, the playbook is not realistic for a real incident.
4. Update the playbook with the gaps you found.

The kill-switch commands and the API endpoint must work in staging
within 90 days, or the runbook is wrong about its blast radius.
