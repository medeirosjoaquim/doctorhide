# doctorhide

A zero-knowledge secrets-manager service.

- **Humans** sign in with username + password, then a required TOTP second factor
  (Google Authenticator), enrolled by scanning a QR code on first login, with one-time
  backup codes (downloadable as a PDF).
- **Machines** authenticate with API keys (`Authorization: Bearer dh_live_...`) that belong
  to **service accounts** (machine identities decoupled from people). Keys are stored hashed
  and the secret is shown only once, at mint time.
- **Secrets** live in projects, encrypted client-side under a passphrase the server never
  sees (PBKDF2 + Fernet); the REST API returns ciphertext, never plaintext.
- `GET /whoami` is a probe endpoint reachable by either path; it reports the current principal.
- Browsable docs are served at `/docs`.

## Quick start with Docker Compose

The fastest way to run the whole stack (app + Postgres). Requires Docker.

1. Create your `.env` from the example and set, at minimum, a superuser password:

   ```bash
   cp .env.example .env
   # then edit .env and set DJANGO_SUPERUSER_PASSWORD (compose refuses to start without it)
   ```

2. Bring it up:

   ```bash
   docker compose up --build
   ```

   This starts three services in order: **db** (Postgres 17, host port 5433) → **init**
   (runs migrations and auto-creates the admin from `DJANGO_SUPERUSER_*`, idempotent — a
   no-op if the user already exists) → **app** (gunicorn on http://127.0.0.1:8000/).

   The `init` service **fails fast** if `DJANGO_SUPERUSER_PASSWORD` is unset, so the app
   never boots without an admin account. Username defaults to `admin`; override with
   `DJANGO_SUPERUSER_USERNAME` / `DJANGO_SUPERUSER_EMAIL`.

3. Log in at http://127.0.0.1:8000/login with the superuser you configured (you'll enroll
   TOTP on first login — see [Using it](#using-it)).

To stop: `docker compose down` (add `-v` to also drop the database volume).

## Manual setup (without Compose)

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (Python package/venv manager)
- Docker (for Postgres)
- Python 3.13 (uv will provision it)

## Setup

### 1. Create the virtualenv and install dependencies

```bash
uv venv venv
uv pip install --python venv/bin/python -r requirements.txt
```

Activate it for the commands below:

```bash
source venv/bin/activate
```

### 2. Start Postgres

```bash
docker run -d \
  --name doctorhide-postgres \
  -e POSTGRES_DB=doctorhide \
  -e POSTGRES_USER=doctorhide \
  -e POSTGRES_PASSWORD=doctorhide \
  -p 5433:5432 \
  -v doctorhide_pgdata:/var/lib/postgresql/data \
  postgres:17
```

Host port is **5433** to avoid clashing with any Postgres already on 5432. Verify it's up:

```bash
docker exec doctorhide-postgres pg_isready -U doctorhide
```

### 3. Configure the database connection

The app loads DB settings from a `.env` file in the project root (gitignored). Copy the
example and adjust if needed:

```bash
cp .env.example .env
```

It contains:

- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`
- `POSTGRES_HOST`, `POSTGRES_PORT`

The defaults match the `docker run` above (host `127.0.0.1`, port `5433`), so it works as-is.
Real environment variables set in the process take precedence over `.env`. In docker-compose
later, set `POSTGRES_HOST=db` and `POSTGRES_PORT=5432`.

### 4. Apply migrations

```bash
python manage.py migrate
```

### 5. Create a superuser

```bash
python manage.py createsuperuser
```

### 6. Run the server

```bash
python manage.py runserver
```

App is now at http://127.0.0.1:8000/.

## Using it

### Human login (with TOTP)

1. Go to http://127.0.0.1:8000/login and enter your superuser credentials.
2. **First login:** you'll be shown a QR code. Scan it with Google Authenticator (or any TOTP
   app), enter the 6-digit code to confirm, then **save the backup codes** — they are shown
   only once.
3. **Later logins:** after the password, you'll be asked for the current 6-digit code (or a
   backup code).
4. Once signed in, visit http://127.0.0.1:8000/whoami — it returns
   `{"type": "user", "username": "..."}`.

### Machine access (API keys)

1. Sign in to the admin at http://127.0.0.1:8000/admin/.
2. Under **Iam → Service accounts**, create a service account (e.g. `billing-api-prod`).
3. Select it in the list, choose the **"Mint a new API key"** action, and run it. The full
   key is shown once in the confirmation banner — copy it immediately.
4. Use it:

   ```bash
   curl http://127.0.0.1:8000/whoami \
     -H "Authorization: Bearer dh_live_xxxxxxxx_yyyyyyyy"
   ```

   Returns `{"type": "service_account", "name": "billing-api-prod"}`.
5. To revoke, select the key under **Iam → API keys** and run the **"Revoke selected API
   keys"** action. Revoked or expired keys return `401`.

## Reading secrets via the API

A **project API key** (`dhk_...`) reads the secrets in one project. Mint one from a
project's page in the web app — it's shown only once.

List the secret names (values are never returned):

```bash
KEY="dhk_xxxxxxxx_yyyyyyyy"
curl http://127.0.0.1:8000/api/secrets -H "Authorization: Bearer $KEY"
```

```json
{"project_id":"proj_...","kdf":"pbkdf2-sha256","salt":"zbMsfdEneFZ5x+NexKeH2g==",
 "iterations":600000,"count":1,"limit":100,"offset":0,"keys":["test"]}
```

Fetch one secret. **The API returns the encrypted value, not the plaintext** — it
returns the `ciphertext` plus the key-derivation metadata (`salt`, `iterations`). The
server is zero-knowledge: it never has your passphrase, so it cannot decrypt. You
decrypt **locally** with the passphrase (the "Salt" you set when creating the project):

```bash
curl http://127.0.0.1:8000/api/secrets/test -H "Authorization: Bearer $KEY"
```

```json
{"project_id":"proj_...","kdf":"pbkdf2-sha256","salt":"zbMsfdEneFZ5x+NexKeH2g==",
 "iterations":600000,"key":"test","ciphertext":"gAAAAA...","payload_type":"string"}
```

### Decrypting the value

The scheme is PBKDF2-HMAC-SHA256 (32 bytes) → a Fernet (AES-128-CBC + HMAC) key. The
stored `ciphertext` is `base64url(fernet_token)`, so decode that outer layer **before**
Fernet-decrypting.

**Python** (needs `cryptography`):

```python
import base64, requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

API = "http://127.0.0.1:8000"
KEY = "dhk_xxxxxxxx_yyyyyyyy"
PASSPHRASE = "the project's Salt"

doc = requests.get(f"{API}/api/secrets/test",
                   headers={"Authorization": f"Bearer {KEY}"}).json()

kdf = PBKDF2HMAC(algorithm=SHA256(), length=32,
                 salt=base64.b64decode(doc["salt"]),
                 iterations=doc["iterations"])
fernet_key = base64.urlsafe_b64encode(kdf.derive(PASSPHRASE.encode()))
token = base64.urlsafe_b64decode(doc["ciphertext"])   # undo the outer base64 layer
print(Fernet(fernet_key).decrypt(token).decode())
```

**JavaScript** (Node 18+, no dependencies):

```javascript
import crypto from "node:crypto";

const API = "http://127.0.0.1:8000";
const KEY = "dhk_xxxxxxxx_yyyyyyyy";
const PASSPHRASE = "the project's Salt";

const doc = await (await fetch(`${API}/api/secrets/test`, {
  headers: { Authorization: `Bearer ${KEY}` },
})).json();

const dk = crypto.pbkdf2Sync(
  PASSPHRASE, Buffer.from(doc.salt, "base64"), doc.iterations, 32, "sha256");
const tokenStr = Buffer.from(doc.ciphertext, "base64url").toString("latin1"); // outer layer
const token = Buffer.from(tokenStr, "base64url");                              // fernet token

// Fernet token: version(1) | timestamp(8) | iv(16) | ciphertext | hmac(32)
const signingKey = dk.subarray(0, 16);
const encKey = dk.subarray(16, 32);
const body = token.subarray(0, token.length - 32);
const hmac = token.subarray(token.length - 32);
const expected = crypto.createHmac("sha256", signingKey).update(body).digest();
if (!crypto.timingSafeEqual(hmac, expected)) throw new Error("wrong passphrase");
const iv = token.subarray(9, 25);
const ct = token.subarray(25, token.length - 32);
const decipher = crypto.createDecipheriv("aes-128-cbc", encKey, iv);
console.log(Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8"));
```

A ready-made shell wrapper for the Python flow ships at `bin/dh-get`:

```bash
DH_KEY="dhk_xxxxxxxx_yyyyyyyy" bin/dh-get test   # prompts for the passphrase
```

## Running tests

```bash
python manage.py test
```

## Security notes

- **Secrets stay out of git.** `.gitignore` excludes `.env`, key/cert files, the `secrets/`
  directory, and local DB files. Commit `.env.example`, never `.env`.
- **API key secrets are never stored** — only a SHA-256 hash. The plaintext is surfaced once
  at mint time and is unrecoverable afterward.
- **TOTP** uses a ±30s drift window and rejects a code that's already been used (replay
  protection), and is required for every human account.
- **Production config is env-driven.** `SECRET_KEY`, `DJANGO_DEBUG`, and `ALLOWED_HOSTS` are
  read from the environment (see `.env.example`). Set `DJANGO_ENV=production` to require
  `SECRET_KEY` and enable HTTPS hardening (SSL redirect, HSTS, secure cookies), and serve
  behind TLS.
