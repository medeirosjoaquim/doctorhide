#!/usr/bin/env node
// Fetch a doctorhide secret over the API and decrypt it locally.
//
// The server is zero-knowledge: it returns only the ciphertext plus the
// key-derivation metadata (salt, iterations). The passphrase — the "Salt" you
// set when creating the project — never leaves this machine; decryption happens
// here. Node 18+ only, no dependencies (uses built-in crypto + fetch).
//
// Usage:
//   DH_KEY=dhk_... DH_PASSPHRASE=... node examples/fetch_and_decrypt.mjs <secret-key>
//   DH_KEY=dhk_... node examples/fetch_and_decrypt.mjs <secret-key>   # prompts for passphrase
//
// Environment:
//   DH_KEY         project API key (dhk_...)               [required]
//   DH_PASSPHRASE  project passphrase / Salt               [prompted if unset]
//   DH_BASE_URL    API base URL (default http://127.0.0.1:8000)
//
// Examples:
//   DH_KEY=dhk_a7c6... DH_PASSPHRASE=hunter2 node examples/fetch_and_decrypt.mjs test
//   DH_KEY=dhk_a7c6... node examples/fetch_and_decrypt.mjs test

import crypto from "node:crypto";
import readline from "node:readline";

async function fetchSecret(baseUrl, apiKey, key) {
  const resp = await fetch(`${baseUrl}/api/secrets/${key}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  if (!resp.ok) {
    throw new Error(`API error ${resp.status}: ${await resp.text()}`);
  }
  return resp.json();
}

// Derive the key (PBKDF2-HMAC-SHA256, 32 bytes) and Fernet-decrypt.
// The stored ciphertext is the Fernet token itself (urlsafe-base64), so decode
// it once to get the raw token: version(1) | timestamp(8) | iv(16) | ciphertext | hmac(32).
function decryptSecret(doc, passphrase) {
  const dk = crypto.pbkdf2Sync(
    passphrase, Buffer.from(doc.salt, "base64"), doc.iterations, 32, "sha256");

  const token = Buffer.from(doc.ciphertext, "base64url");

  const signingKey = dk.subarray(0, 16);
  const encKey = dk.subarray(16, 32);

  const body = token.subarray(0, token.length - 32);
  const hmac = token.subarray(token.length - 32);
  const expected = crypto.createHmac("sha256", signingKey).update(body).digest();
  if (hmac.length !== expected.length || !crypto.timingSafeEqual(hmac, expected)) {
    throw new Error("decryption failed: wrong passphrase for this project");
  }

  const iv = token.subarray(9, 25);
  const ct = token.subarray(25, token.length - 32);
  const decipher = crypto.createDecipheriv("aes-128-cbc", encKey, iv);
  const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  return doc.payload_type === "binary" ? plaintext : plaintext.toString("utf8");
}

function promptHidden(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    // Mask input so the passphrase is not echoed.
    const onData = () => { rl.output.write(`\x1B[2K\x1B[200D${prompt}`); };
    process.stdin.on("data", onData);
    rl.question(prompt, (answer) => {
      process.stdin.removeListener("data", onData);
      rl.close();
      process.stdout.write("\n");
      resolve(answer);
    });
  });
}

async function main() {
  const key = process.argv[2];
  if (!key) {
    console.error("usage: DH_KEY=dhk_... [DH_PASSPHRASE=...] node examples/fetch_and_decrypt.mjs <secret-key>");
    process.exit(2);
  }
  const apiKey = process.env.DH_KEY;
  if (!apiKey) {
    console.error("DH_KEY is required (your dhk_ project API key)");
    process.exit(2);
  }
  const baseUrl = process.env.DH_BASE_URL || "http://127.0.0.1:8000";
  const passphrase = process.env.DH_PASSPHRASE
    || await promptHidden("Passphrase (the project's Salt): ");

  const doc = await fetchSecret(baseUrl, apiKey, key);
  if (!doc.ciphertext) {
    console.error(`no ciphertext in response: ${JSON.stringify(doc)}`);
    process.exit(1);
  }
  const value = decryptSecret(doc, passphrase);
  if (Buffer.isBuffer(value)) {
    process.stdout.write(value);
  } else {
    console.log(value);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
