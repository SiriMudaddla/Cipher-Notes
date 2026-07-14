# CipherNotes

A multi-user, encrypted notes app built with Streamlit. Anyone can create
their own account with a username, email, and password. Notes can be
organized into folders, and specific notes can be shared with other
accounts using real public-key encryption - not just a "visible" flag.

## Features

- **Accounts** - sign up with a username, email, and password; log in/out
- **Email-based password reset** - a 6-digit one-time code is emailed to reset a forgotten password without losing your notes
- **Folders** - organize notes into folders you create on the fly
- **Sharing** - share a specific note with another account; only that account can decrypt it
- **Biometric login (passkeys)** - unlock with Windows Hello, Touch ID, Face ID, or your device's screen lock, using the standard WebAuthn protocol
- **PBKDF2 key derivation** - your password is turned into an AES key via PBKDF2-HMAC-SHA256 (390,000 iterations)
- **AES-GCM encryption** - every note (and every past version of every note) is encrypted separately, with a fresh random nonce each time
- **Per-user isolation** - one account's notes are never visible to, or decryptable by, another account unless explicitly shared
- **Rate limiting** - accounts lock out for 5 minutes after 5 wrong password/OTP attempts; OTP codes expire after 10 minutes, allow only 5 guesses, and have a 60-second resend cooldown
- **Version history** - every edit keeps the old version, restorable anytime
- **Import/export** - download or upload a JSON backup of your (still-encrypted) notes
- **Biometric tab** - placeholder for a future Windows Hello integration (local-only feature, not part of the hosted app)

## How the security works, in plain terms

### The master key model

Each account has one random 256-bit "master key" - this is what actually
encrypts and decrypts your notes. It's generated once at signup and never
changes. The master key is wrapped (encrypted) twice, independently:

- once under a key derived from your **password**
- once under a key derived from the **server's own secret** (`APP_SECRET_KEY`)

Your password unwraps the master key for normal logins. The server-secret
copy exists so that email-based "forgot password" can reset your password
without losing access to your existing notes.

**Trade-off worth knowing:** because the server can unwrap its own copy
of the master key on its own (via `APP_SECRET_KEY`), whoever controls the
deployed app's secret and database technically has enough information to
decrypt any account's notes without that account's password. This is the
same trade-off almost every app with an email-based "reset password"
feature makes. Protect `APP_SECRET_KEY` like a database password.

### Sharing: real public-key encryption, not a visibility flag

Every account also gets an RSA-2048 keypair at signup. The private key is
wrapped under the account's own master key (so it's only usable once
they've logged in); the public key is stored as-is, since public keys are
meant to be shared.

To share a note with someone:
1. A brand-new one-time AES key is generated just for this share.
2. The note's title and content are re-encrypted with that one-time key.
3. The one-time key itself is encrypted with the **recipient's public
   key** (RSA-OAEP).

Only the recipient's private key - unlocked by their own password - can
open that one-time key, and therefore the note. The original owner's
master key is never exposed to anyone else, and nobody but the intended
recipient can decrypt the shared copy, even with full database access
(short of also having `APP_SECRET_KEY` and that recipient's password).

**A share is a snapshot, not a live view.** If you edit the original note
afterward, the person you shared it with keeps seeing the version from
the moment you shared it - re-share it to update what they see. You can
revoke a share at any time from the note's "Share" section.

### Step by step (password + notes)

1. At signup, PBKDF2-HMAC-SHA256 (390,000 rounds) turns your password + a
   random salt into a key that wraps the master key. The master key is
   also wrapped under the server's secret, and an RSA keypair is
   generated for sharing.
2. Every note is encrypted with the **master key** using AES-GCM and a
   brand-new random nonce each time. AES-GCM also detects tampering.
3. If you forget your password: enter your username or email on the
   "Forgot password" tab. A 6-digit code is emailed to your registered
   address (or shown on screen in local dev mode - see below).
4. OTP codes expire after 10 minutes, allow only 5 wrong guesses, and can
   only be requested once every 60 seconds per account.
5. Requesting a reset always returns the same message regardless of
   whether the username/email exists, so it can't be used to check which
   accounts are registered.

### Biometric login (WebAuthn / passkeys)

This is the real, standard cross-platform mechanism - not a
Windows-specific or Apple-specific integration. One protocol (WebAuthn),
routed by the browser to whatever the device has: Windows Hello, Touch
ID, Face ID, Android biometrics, or a screen lock PIN.

**How it fits the security model:** verifying a passkey proves "this is
the registered device/biometric for this account," but doesn't hand over
anything usable to decrypt that account's notes on its own (WebAuthn is
a signature challenge-response, not a key-exchange, in the simple form
used here). So after a passkey is verified, the app unwraps the master
key using the same server-escrow key already used for email/OTP password
reset (`APP_SECRET_KEY`). This doesn't add a new weakening of the
security model - it reuses the one already made and documented above.

**Configuration** (only matters once deployed - defaults work for local
testing on `localhost`):

```
WEBAUTHN_RP_ID=your-domain.com          # no scheme, no port
WEBAUTHN_RP_NAME=CipherNotes
WEBAUTHN_ORIGIN=https://your-domain.com  # must exactly match the browser's address bar
```

**Passkeys are bound to the exact domain they're registered on.** One
registered while testing on `localhost` will NOT work once deployed to a
real URL - register again there. This is a property of the WebAuthn
standard, not a bug.

**Testing status - please read before relying on this:** every piece of
server-side logic (registration verification, login verification, replay
protection, cloned-device detection, and the master-key unwrapping) was
tested against a synthetic authenticator that produces spec-compliant
responses using a real ECDSA keypair - this proves the cryptographic
verification itself is correct, including rejecting wrong origins,
forged signatures, replayed challenges, and rolled-back sign counts.

What could NOT be tested the same way is the actual browser-to-hardware
step: clicking the button, the browser prompting a real fingerprint
reader or Face ID camera, and the resulting response round-tripping
correctly through the custom component. That requires real devices,
which weren't available while building this. **Test this feature
carefully on your own Windows and Apple devices once deployed** before
depending on it.

## Running it locally

```powershell
pip install -r requirements.txt
streamlit run app.py
```

By default this uses a local SQLite file (`secure_notes.db`).

### Local dev mode for OTP (no email setup required)

If `SMTP_HOST` / `SMTP_USERNAME` / `SMTP_PASSWORD` aren't set, the app
shows the OTP directly on the "Forgot password" screen instead of
emailing it, so you can test locally without setting up a mail account.
**Never leave this on for a real deployment.**

You'll also see a one-time console warning about `APP_SECRET_KEY` not
being set; a value gets auto-generated into a local `.app_secret` file so
things still work across restarts during development. Set a real
`APP_SECRET_KEY` before deploying - if it ever changes, every existing
account's email-reset path breaks (normal password login is unaffected).

## Deploying it for real (so anyone can use it)

### 1. Set two required secrets

```
APP_SECRET_KEY=<a long random string - e.g. output of: python -c "import secrets; print(secrets.token_hex(32))">
```

Keep this exactly the same across restarts/redeploys.

### 2. Configure a real email provider
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=<an app password, not your regular password>
SMTP_FROM=your-email@gmail.com
```

For Gmail: enable 2-Step Verification, then create an "App Password" at
https://myaccount.google.com/apppasswords and use that as `SMTP_PASSWORD`.

### 3. Configure biometric login for your real domain

```
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_RP_NAME=CipherNotes
WEBAUTHN_ORIGIN=https://your-domain.com
```

Passkeys registered during local testing won't work on the deployed
domain - that's expected, register again there. See the "Biometric
login" section above for the full explanation and testing status.

### 4. Set up the database

- SQLite (the local default) is a single file on disk - fine for your
  own machine or a host with *persistent* disk. Not fine on hosts that
  wipe local files on restart/redeploy - your users' accounts and notes
  would disappear.
- For a real public deployment, point at a hosted Postgres database
  instead - no code changes needed, just:

  ```
  DATABASE_URL=postgresql://user:password@host:5432/dbname
  ```

  Free options: Supabase, Neon, or Railway's Postgres add-on.

### Suggested deployment paths

- **Streamlit Community Cloud** + a free Postgres database (Supabase/Neon)
  - set `APP_SECRET_KEY`, the `SMTP_*` variables, the `WEBAUTHN_*`
  variables, and `DATABASE_URL` as secrets in the app settings.
- **Render or Railway** with their own Postgres add-on.
- **A small VPS** - either SQLite with a persistent disk, or Postgres
  running alongside the app.

### Other things worth doing before opening it up publicly

- `secure_notes.db`, `.app_secret`, and `.env` files are already covered
  by `.gitignore`.
- HTTPS: most hosts (Streamlit Community Cloud, Render, Railway) handle
  this automatically, and is required for WebAuthn/passkeys to work
  outside of local development.

## Project structure

```
secure-notes-app/
|-- app.py               # Streamlit UI: sign up / log in / forgot password / notes / sharing / biometric
|-- crypto_utils.py      # PBKDF2, AES-GCM, OTP/server-key, and RSA sharing helpers
|-- db.py                # Multi-user database layer (SQLite locally, Postgres in prod)
|-- email_utils.py       # SMTP sending for the OTP email, with a local dev fallback
|-- webauthn_utils.py    # Server-side passkey registration/login verification
|-- webauthn_bridge.py   # Browser-side component that talks to WebAuthn/biometric hardware
|-- requirements.txt
|-- .gitignore
```

## Limitations to be aware of

- The server operator (whoever holds `APP_SECRET_KEY` and database
  access) can technically decrypt any account's notes - a deliberate
  trade-off for supporting email-based password reset and biometric
  login.
- Biometric login's server-side verification logic was tested against a
  synthetic authenticator (proving the cryptography is correct), but the
  actual browser-to-hardware step has not been tested on real devices -
  test carefully on real Windows/Apple hardware before relying on it.
- Shares are one-time snapshots, not live views - re-share to update
  what a recipient sees.
- Schema changes (like the ones that added folders and sharing) require
  a fresh database locally, since `init_db()` only creates missing
  tables, it doesn't migrate existing ones. A real deployment with real
  users would need a proper migration tool (e.g. Alembic) instead.
- The Biometric tab is a placeholder; Windows Hello integration only
  makes sense for a local install and isn't part of the hosted app.
