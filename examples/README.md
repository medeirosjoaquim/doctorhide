# Examples — fetch & decrypt a secret

Both scripts do the same thing: fetch a secret from the doctorhide API and
decrypt it **locally** with your passphrase. The server is zero-knowledge — it
only ever returns the ciphertext plus the key-derivation metadata (`salt`,
`iterations`), never the plaintext. The passphrase (the "Salt" you set when
creating the project) never leaves your machine.

## Decryption scheme

- Derive a 32-byte key with PBKDF2-HMAC-SHA256 from `passphrase` + `salt` + `iterations`.
- The API's `ciphertext` is the Fernet token itself (already urlsafe-base64).
- Fernet-decrypt it (AES-128-CBC + HMAC) to recover the plaintext.

## Python

Needs the `cryptography` package (already in the project venv).

```bash
DH_KEY=dhk_xxxxxxxx_yyyyyyyy DH_PASSPHRASE='your-salt' \
  ./venv/bin/python examples/fetch_and_decrypt.py test

# or omit DH_PASSPHRASE to be prompted (no echo):
DH_KEY=dhk_xxxxxxxx_yyyyyyyy ./venv/bin/python examples/fetch_and_decrypt.py test
```

## JavaScript

Node 18+ only, no dependencies (built-in `crypto` + `fetch`).

```bash
DH_KEY=dhk_xxxxxxxx_yyyyyyyy DH_PASSPHRASE='your-salt' \
  node examples/fetch_and_decrypt.mjs test

# or omit DH_PASSPHRASE to be prompted:
DH_KEY=dhk_xxxxxxxx_yyyyyyyy node examples/fetch_and_decrypt.mjs test
```

## Environment variables

- `DH_KEY` — project API key (`dhk_...`). Required.
- `DH_PASSPHRASE` — project passphrase / Salt. Prompted if unset.
- `DH_BASE_URL` — API base URL. Default `http://127.0.0.1:8000`.

A wrong passphrase exits non-zero with `decryption failed: wrong passphrase for
this project`. Binary secrets (`payload_type: "binary"`) are written raw to
stdout; string secrets are printed with a trailing newline.
