"""
db.py
-----
Multi-user storage for CipherNotes, built on SQLAlchemy so the exact same
code works with two different databases:

- SQLite (a single file, e.g. secure_notes.db) -- great for running locally
  or on a host with a persistent disk.
- Postgres -- needed on hosts that DON'T give you persistent disk (most
  free/serverless-style hosts wipe local files on every restart). Point
  DATABASE_URL at a free Postgres instance (Supabase, Neon, Railway, etc.)
  and nothing else about the app needs to change.

Which one is used is controlled entirely by the DATABASE_URL environment
variable. If it's not set, we fall back to a local SQLite file so the app
still works out of the box with zero setup.

Key model: each account has one random "master key" that encrypts all of
its notes. It's wrapped (encrypted) twice, independently:
  - once under a key derived from the password (PBKDF2)
  - once under a key derived from the server's own secret (APP_SECRET_KEY)

The password-wrapped copy is used for normal logins. The server-wrapped
copy exists so a "forgot password" email flow can reset the password
without losing access to existing notes.

IMPORTANT TRADE-OFF: because the server can unwrap the server-wrapped
copy on its own (using APP_SECRET_KEY), whoever controls the deployed
app's secret and database technically has enough information to decrypt
any account's notes, without needing that account's password. This is
the same trade-off almost every app with an email-based "reset password"
feature makes. If that's not acceptable for your use case, a user-held
recovery code (never stored anywhere) is the stronger alternative -- just
without the familiar "email me a code" UX.
"""

import os
import time
import uuid

from sqlalchemy import (
    create_engine, text, MetaData, Table, Column,
    Integer, String, Float, Text,
)
from sqlalchemy.exc import IntegrityError

from crypto_utils import (
    generate_salt, derive_key, generate_master_key,
    encrypt, decrypt, encrypt_bytes, decrypt_bytes,
    generate_otp, hash_otp, server_key_from_secret,
    generate_keypair, rsa_encrypt, rsa_decrypt,
    b64, unb64,
)

# --- Connection setup ----------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///secure_notes.db")

_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    # allow SQLite to be used from Streamlit's multi-threaded server
    _connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=_connect_args)

if DATABASE_URL.startswith("sqlite"):
    # WAL mode lets multiple people read/write at the same time without
    # locking each other out -- matters once this is a shared deployment.
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))

# --- App secret (used to wrap the server-side copy of each master key) ---
# In production, ALWAYS set APP_SECRET_KEY as a real environment variable/
# secret. If it isn't set, we fall back to a value auto-generated and
# saved to a local file so local development still works across restarts.
# That fallback file is NOT suitable for production: on hosts without a
# persistent disk it will regenerate on every restart, which permanently
# breaks email-based password reset for any account created under the
# previous secret (their normal password login is unaffected -- only the
# email-reset path depends on this secret staying stable).
_APP_SECRET_FILE = ".app_secret"


def _load_or_create_app_secret() -> str:
    env_secret = os.environ.get("APP_SECRET_KEY")
    if env_secret:
        return env_secret

    if os.path.exists(_APP_SECRET_FILE):
        with open(_APP_SECRET_FILE, "r") as f:
            return f.read().strip()

    new_secret = os.urandom(32).hex()
    with open(_APP_SECRET_FILE, "w") as f:
        f.write(new_secret)
    print(
        "WARNING: APP_SECRET_KEY is not set. Generated a local secret at "
        f"'{_APP_SECRET_FILE}' for development. Set APP_SECRET_KEY as a "
        "real environment variable before deploying -- see README."
    )
    return new_secret


APP_SECRET = _load_or_create_app_secret()
SERVER_KEY = server_key_from_secret(APP_SECRET)

metadata = MetaData()

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(64), unique=True, nullable=False),
    Column("email", String(255), unique=True, nullable=False),
    Column("salt", Text, nullable=False),
    # master key, wrapped under the password-derived key
    Column("pw_wrapped_nonce", Text, nullable=False),
    Column("pw_wrapped_ciphertext", Text, nullable=False),
    # master key, wrapped under the server secret (for email-OTP reset)
    Column("server_wrapped_nonce", Text, nullable=False),
    Column("server_wrapped_ciphertext", Text, nullable=False),
    # RSA keypair, used only for sharing notes with other accounts.
    # public_key is plain text (it's meant to be public). private_key is
    # wrapped under the account's own master key -- so it's only usable
    # after the account has logged in and unlocked that key, same as
    # everything else.
    Column("public_key", Text, nullable=False),
    Column("priv_wrapped_nonce", Text, nullable=False),
    Column("priv_wrapped_ciphertext", Text, nullable=False),
    Column("created_at", Float, nullable=False),
)

notes = Table(
    "notes", metadata,
    Column("id", String(36), primary_key=True),
    Column("user_id", Integer, nullable=False),
    Column("title", Text, nullable=False),
    Column("folder", Text, nullable=True),  # None/empty = "Uncategorized"
    Column("current_nonce", Text, nullable=False),
    Column("current_ciphertext", Text, nullable=False),
    Column("updated_at", Float, nullable=False),
)

note_history = Table(
    "note_history", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("note_id", String(36), nullable=False),
    Column("nonce", Text, nullable=False),
    Column("ciphertext", Text, nullable=False),
    Column("timestamp", Float, nullable=False),
)

# A "share" is a self-contained encrypted snapshot of a note, made
# specifically for one recipient at the moment of sharing. It's not a
# live view of the original -- if the owner edits the note afterward,
# the recipient still sees the version that was shared, until re-shared.
# This keeps the crypto simple and avoids ever handing out the owner's
# own key. Both the title and the content are encrypted; only the
# recipient's private key can open either.
note_shares = Table(
    "note_shares", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("owner_user_id", Integer, nullable=False),
    Column("recipient_user_id", Integer, nullable=False),
    Column("source_note_id", String(36), nullable=True),  # for reference only
    # the one-time AES key used for this share, itself encrypted with the
    # recipient's RSA public key
    Column("wrapped_key", Text, nullable=False),
    Column("title_nonce", Text, nullable=False),
    Column("title_ciphertext", Text, nullable=False),
    Column("content_nonce", Text, nullable=False),
    Column("content_ciphertext", Text, nullable=False),
    Column("shared_at", Float, nullable=False),
)

login_attempts = Table(
    "login_attempts", metadata,
    Column("username", String(64), primary_key=True),
    Column("failed_count", Integer, nullable=False),
    Column("locked_until", Float, nullable=True),
)

otp_codes = Table(
    "otp_codes", metadata,
    Column("username", String(64), primary_key=True),
    Column("otp_hash", Text, nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("attempts", Integer, nullable=False),
    Column("created_at", Float, nullable=False),
)

# Registered passkeys (WebAuthn credentials). One account can register
# several devices (a laptop's Windows Hello, a phone's Face ID, etc.).
# public_key is stored as raw bytes (COSE-encoded) exactly as the
# webauthn library produced it, since verification needs it back in that
# same form.
webauthn_credentials = Table(
    "webauthn_credentials", metadata,
    Column("id", Integer, primary_key=True,
