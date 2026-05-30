# In-App Docs Page

## What was built

- New route `/docs` (named `accounts:docs`, no trailing slash, matching every other route in the project). Wired into the existing `accounts` app, whose urls are mounted at root `''`.
- Renders HTTP 200; `reverse('accounts:docs')` resolves to `/docs`.
- Files created:
  - `/home/asari/doctorhide/accounts/templates/accounts/docs.html` — extends `accounts/base.html`, fills the `title` and `body` blocks, body wrapped in the existing `.container` class, with an on-page table-of-contents `<nav>` linking five section anchors.
- Files modified:
  - `/home/asari/doctorhide/accounts/views.py` — added `def docs(request): return render(request, "accounts/docs.html")` after the existing `home` view. No new imports, no app logic touched.
  - `/home/asari/doctorhide/accounts/urls.py` — added `path("docs", views.docs, name="docs")` after the home route.
- Suite status: green. `venv/bin/python manage.py test` ran 204 tests, OK. No regressions. The existing backup-codes PDF view/route was left untouched.

## Sections & examples

- **Getting started** (`#getting-started`) — signup (username + password1/password2, case-insensitive uniqueness, Django password validation), mandatory first-login TOTP enrollment via QR / manual secret, login + verify flow (TOTP or one-time backup code), and the 10 one-time backup codes.
- **Using the web app** (`#using-the-web-app`) — project create/unlock with a "Salt" passphrase (never stored — lose it, lose the secrets), auto-unlock on create, adding/updating secrets (`key`/`value`, update-in-place), revealing via `?reveal=<secret pk>`, and managing `dhk_`-prefixed project API keys (shown once, masked thereafter, revocable).
- **API reference** (`#api-reference`) — GET-only endpoints: `/api/secrets` (returns metadata `project_id`, `kdf` = `pbkdf2-sha256`, `salt`, `iterations`, plus a `keys` array — no ciphertext) and `/api/secrets/<path:key>` (adds `key` + `ciphertext`; 404 `{"detail":"Not found."}`). `Authorization: Bearer dhk_<key_id>_<secret>` header. Also `/whoami`.
- **Decrypting a secret** (`#decrypting-a-secret`) — client-side decryption: standard-base64 salt decode, PBKDF2-HMAC-SHA256 (length 32, default 600000 iterations), url-safe base64 Fernet key, Fernet decrypt. **This example was executed against the real `vault/crypto.py`**: a full round-trip succeeded, the client-derived key matched `crypto.derive_key` byte-for-byte, and a wrong passphrase raised `InvalidToken`.
- **Security model** (`#security-model`) — zero-knowledge vault: server stores only `salt`, `iterations`, and a `verifier` (never the passphrase or plaintext); KDF and Fernet (AES-128-CBC + HMAC) details; API keys stored as prefix + sha256 hash + last-four (raw secret unrecoverable). Documents the existing first-login backup-codes PDF download (`/totp/backup-codes.pdf`, `application/pdf`, single-use static codes).

## Accuracy notes

The verify phase corrected several real errors before the examples were embedded:

- **Web UI / API response shape**: draft wrongly said `/api/secrets` returns ciphertext. It returns metadata + a `keys` array only; ciphertext comes from `/api/secrets/<key>`. Rewritten.
- **API key format**: draft implied the project `public_id` is embedded in the key (`dhk_<public_id>_<secret>`). The middle segment is an independent per-key id (`secrets.token_hex(8)`), not the project id (which is `proj_<hex>` and appears separately as `project_id`). Changed to `dhk_<key_id>_<secret>`.
- **API reference**: two vault curl examples used `https://` against a plain dev server; corrected to `http://`. Routes, methods, headers, fields, and constants otherwise verified correct.
- **Decryption example**: crypto logic was already correct; placeholders normalized to `dhk_<key_id>_<secret>` and the example `project_id` shown as a `proj_...` string.
- **Getting started** and **Security model**: examples matched the code as drafted; no changes required.

## How to view

Run the dev server yourself (this agent does not start servers), then open the page:

```bash
cd /home/asari/doctorhide && venv/bin/python manage.py runserver
```

Then visit `http://127.0.0.1:8000/docs`.
