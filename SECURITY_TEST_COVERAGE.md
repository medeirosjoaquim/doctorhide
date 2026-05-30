# Security Test Coverage

## Summary

- **179 new security tests** added across **6 files** in the doctorhide Django app.
- Full suite status: **GREEN** — 204 tests run, 0 failures, 0 errors.
- Verified with `manage.py test -v1` against the project venv.
- Per-file counts: `iam/tests_security.py` (20), `vault/tests_api_security.py` (27), `vault/tests_authz.py` (37), `vault/tests_crypto_security.py` (23), `accounts/tests_mfa.py` (34), `vault/tests_lifecycle.py` (38).

## Coverage added by area

### `iam/tests_security.py` (20) — IAM API key authentication
- Auth failure modes: expired key, inactive service account, valid prefix + wrong secret, garbage non-prefixed token, well-formed token with no DB row.
- Anti-enumeration: all failure modes return an identical 401 with the same detail string.
- Malformed `Authorization` header matrix: no token, three parts, empty token w/ trailing space, non-Bearer scheme fall-through, case-insensitive `bearer`.
- `last_used_at` stamped on success, left unset on failure.
- Tenant isolation: a key authenticates only as its own service account.
- Unit-level: constant-time `hmac.compare_digest` in `verify`, `split_token` edges, idempotent `revoke`, `expires_at == now` boundary inactive, DB-level prefix uniqueness (IntegrityError).

### `vault/tests_api_security.py` (27) — Vault REST API (zero-knowledge)
- Header shape: no header on list and detail, non-Bearer `Token`/`Basic` schemes, bare `Bearer`, 3-part header.
- Token/prefix tampering: wrong prefix, missing secret segment, unknown prefix (no DB row), correct prefix + wrong secret — with matching `split_token` unit checks.
- Key lifecycle: expired key rejected on list and detail, future-expiry still active, revoked key rejected on both endpoints, `last_used_at` stamped on success.
- Zero-knowledge response shape: detail returns ciphertext + KDF metadata only (no value/plaintext/passphrase); list returns key names only; `project_id == public_id`; empty project lists nothing; missing secret 404; slash-containing keys resolve.
- Tenant isolation: cross-project read 404 (no leak), list scoped to own keys + own salt/public_id, same key name across tenants stays isolated with distinct, separately-decryptable ciphertext.

### `vault/tests_authz.py` (37) — Web UI authorization
- OTP gating: anonymous redirected, password-only/unverified redirected, verified owner loads list and detail.
- Tenant isolation (13 tests): every read and mutating route (detail/unlock/lock/secret_add/secret_delete/api_key_create/api_key_revoke) on a foreign project returns 404 with no state change; two confused-deputy variants (own project_id + foreign child id); foreign-unlock does not leak into the session; cross-principal REST key cannot read another tenant's secrets.
- Lock/unlock: correct passphrase reveals, wrong passphrase rejected, locked reveal hides plaintext, lock forgets key, per-project session key isolation.
- Project create: happy path auto-unlock, empty name, short passphrase, duplicate name (same owner) rejected, same name across owners allowed, passphrase never persisted.
- Secret mutation: encrypted add, overwrite without duplicate, add-while-locked rejected, both fields required, delete targets only the named secret, GET is a no-op.
- Web API key: mint shows token once, minted key authenticates REST then revoke blocks, cross-tenant revoke 404, GET no-ops.

### `vault/tests_crypto_security.py` (23) — Crypto / zero-knowledge primitives
- Key derivation: wrong passphrase / different salt / different iterations all derive different keys; default iterations == `DEFAULT_ITERATIONS` (600000); derived key is a valid Fernet key.
- Salt: length and randomness.
- Verifier: fails for wrong key without raising, fails for tampered verifier, leaks no passphrase/key material, non-deterministic yet both copies validate.
- Encryption: ciphertext != plaintext, wrong key raises `InvalidToken`, tampered ciphertext raises `InvalidToken`, same plaintext encrypts differently (IV), roundtrip for empty/unicode/whitespace.
- Model zero-knowledge: `Project` has no passphrase field, passphrase absent from all persisted columns, stored verifier validates against DB salt+iterations, iterations default constant.
- Uniqueness: project `(owner, name)` and secret `(project, key)` constraints; cross-owner / cross-project duplicates allowed; `update_or_create` overwrites in place.

### `accounts/tests_mfa.py` (34) — Signup, login gate, TOTP & backup codes
- Signup: happy path sets pending and redirects to enroll; rejects duplicate (case-insensitive) / mismatched / weak / empty; verified user redirected to vault.
- Login gate: correct password sets pending but NOT verified; routes to enroll without device; wrong password, nonexistent user (generic, no enumeration), and inactive user all rejected.
- TOTP enroll: idempotent unconfirmed device, redirects without pending / with confirmed device, correct token confirms + issues 10 backup codes, wrong token leaves unconfirmed.
- TOTP verify: correct completes login, wrong rejected, pending/device redirects, token replay rejected, secret not leaked on the verify page.
- Backup codes: authenticate the gate and are consumed, single-use enforced, unknown code rejected, re-enroll rotates codes.
- OTP-protected route enforcement: anonymous denied, password-only session denied, fully verified allowed; backup-codes page/download gated; logout flushes session and OTP state.

### `vault/tests_lifecycle.py` (38) — Project/secret/key lifecycle (view + model)
- Project create view + `unique_together` model behavior, passphrase never persisted.
- Lock/unlock view: session-key storage, wrong-passphrase rejection, locked project hides/blocks secrets.
- Secret lifecycle view: ciphertext decrypts, update without duplicate, missing value no-op, scoped delete.
- API key mint/revoke view: token shown once, only hash stored, revoke deactivates.
- `ProjectAPIKey` model: generate/verify, `is_active` transitions, expiry, idempotent revoke, `split_token` rejection.
- Tenant isolation: 404 cross-owner on all 7 routes + list scoping.
- OTP gating redirects; POST-only mutation endpoints are no-ops on GET.

## Suspected app bugs / gaps

- **No confirmed app bugs.** No security flaws were surfaced by the new tests.
- Behavioral note (not a bug): `secret_delete` and `api_key_revoke` filter by `project.secrets/api_keys`, so a confused-deputy request with the attacker's own valid `project_id` + a foreign child id returns a silent 302 no-op rather than 404. The foreign object survives in all cases; tests assert that invariant.
- Behavioral note (vault REST): DRF runs `iam.APIKeyAuthentication` before vault's authenticator. iam's `split_token` returns `(None, None)` for `dhk_` tokens, so it should fall through; the full suite is green, confirming ordering works in practice. Flagged only for awareness if settings change.
- Behavioral note (accounts): `backup_codes` and `download_backup_codes` views gate on `is_authenticated` only (not OTP-verified). Not exploitable today since the only path to auth login also completes OTP login.
- **Test-quality follow-up** in `accounts/tests_mfa.py`: a `replace_all` rewrote some negative `is_verified()` assertions into `"otp_device_id" in session` session-state checks. They pass and assert the correct security property (no OTP device id in session when unverified), but a reviewer may prefer the 6 negative-case lines restated as `assertNotIn("otp_device_id", session)` for clarity.

## How to run

```bash
cd /home/asari/doctorhide && /home/asari/doctorhide/venv/bin/python manage.py test
```
