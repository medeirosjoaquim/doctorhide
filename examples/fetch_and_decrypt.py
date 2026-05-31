#!/usr/bin/env python3
"""Fetch a doctorhide secret over the API and decrypt it locally.

The server is zero-knowledge: it returns only the ciphertext plus the
key-derivation metadata (salt, iterations). The passphrase — the "Salt" you set
when creating the project — never leaves this machine; decryption happens here.

Requires the `cryptography` package (already in the project venv).

Usage:
    DH_KEY=dhk_... DH_PASSPHRASE=... python examples/fetch_and_decrypt.py <secret-key>
    DH_KEY=dhk_... python examples/fetch_and_decrypt.py <secret-key>   # prompts for passphrase

Environment:
    DH_KEY         project API key (dhk_...)               [required]
    DH_PASSPHRASE  project passphrase / Salt               [prompted if unset]
    DH_BASE_URL    API base URL (default http://127.0.0.1:8000)

Examples:
    DH_KEY=dhk_a7c6... DH_PASSPHRASE=hunter2 python examples/fetch_and_decrypt.py test
    DH_KEY=dhk_a7c6... python examples/fetch_and_decrypt.py test
"""
import base64
import getpass
import json
import os
import sys
import urllib.request

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def fetch_secret(base_url, api_key, key):
    """GET one secret; returns the JSON dict (ciphertext + KDF metadata)."""
    req = urllib.request.Request(
        f"{base_url}/api/secrets/{key}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def decrypt_secret(doc, passphrase):
    """Derive the Fernet key from passphrase + salt + iterations and decrypt.

    The stored ciphertext is base64url(fernet_token), so the outer base64 layer
    is removed before Fernet decryption."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=base64.b64decode(doc["salt"]),
        iterations=doc["iterations"],
    )
    fernet_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    token = base64.urlsafe_b64decode(doc["ciphertext"].encode())
    plaintext = Fernet(fernet_key).decrypt(token)
    if doc.get("payload_type") == "binary":
        return plaintext  # bytes
    return plaintext.decode()


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: DH_KEY=dhk_... [DH_PASSPHRASE=...] python examples/fetch_and_decrypt.py <secret-key>")
    key = argv[1]

    api_key = os.environ.get("DH_KEY")
    if not api_key:
        sys.exit("DH_KEY is required (your dhk_ project API key)")
    base_url = os.environ.get("DH_BASE_URL", "http://127.0.0.1:8000")
    passphrase = os.environ.get("DH_PASSPHRASE") or getpass.getpass(
        "Passphrase (the project's Salt): "
    )

    try:
        doc = fetch_secret(base_url, api_key, key)
    except urllib.error.HTTPError as exc:
        sys.exit(f"API error {exc.code}: {exc.read().decode(errors='replace')}")

    if "ciphertext" not in doc:
        sys.exit(f"no ciphertext in response: {json.dumps(doc)}")

    try:
        value = decrypt_secret(doc, passphrase)
    except InvalidToken:
        sys.exit("decryption failed: wrong passphrase for this project")

    if isinstance(value, bytes):
        sys.stdout.buffer.write(value)
    else:
        print(value)


if __name__ == "__main__":
    main(sys.argv)
