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
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False),
    Column("credential_id", Text, unique=True, nullable=False),  # base64url
    Column("public_key", Text, nullable=False),  # base64 of raw COSE bytes
    Column("sign_count", Integer, nullable=False),
    Column("nickname", Text, nullable=False),
    Column("created_at", Float, nullable=False),
)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60       # 5 minutes
OTP_TTL_SECONDS = 10 * 60      # OTP codes expire after 10 minutes
OTP_MAX_ATTEMPTS = 5           # wrong-OTP guesses allowed before it's dead
OTP_RESEND_COOLDOWN = 60       # seconds between OTP requests for the same account


def init_db():
    metadata.create_all(engine)


# --- Rate limiting helpers (shared by login and OTP verification) ---------

def _check_lockout(username: str):
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT locked_until FROM login_attempts WHERE username = :u"),
            {"u": username},
        ).fetchone()
    if row is not None and row[0] is not None and row[0] > time.time():
        minutes_left = max(1, int((row[0] - time.time()) / 60) + 1)
        return f"Too many failed attempts. Try again in about {minutes_left} minute(s)."
    return None


def _record_attempt(username: str, success: bool):
    now = time.time()
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT failed_count FROM login_attempts WHERE username = :u"),
            {"u": username},
        ).fetchone()

        if success:
            conn.execute(text("DELETE FROM login_attempts WHERE username = :u"), {"u": username})
            return

        if row is None:
            conn.execute(
                login_attempts.insert().values(username=username, failed_count=1, locked_until=None)
            )
        else:
            new_count = row[0] + 1
            new_locked_until = now + LOCKOUT_SECONDS if new_count >= MAX_FAILED_ATTEMPTS else None
            if new_locked_until is not None:
                new_count = 0
            conn.execute(
                login_attempts.update().where(login_attempts.c.username == username).values(
                    failed_count=new_count, locked_until=new_locked_until
                )
            )


# --- Accounts --------------------------------------------------------------

def username_exists(username: str) -> bool:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT 1 FROM users WHERE username = :u"), {"u": username}
        ).fetchone()
        return row is not None


def get_username(user_id: int):
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT username FROM users WHERE id = :uid"), {"uid": user_id}
        ).fetchone()
        return row[0] if row else None


def email_exists(email: str) -> bool:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT 1 FROM users WHERE email = :e"), {"e": email}
        ).fetchone()
        return row is not None


def create_user(username: str, email: str, password: str):
    """Creates a brand-new account.

    Returns (user_id, master_key, error). On failure, error explains why
    (username or email already taken)."""
    if username_exists(username):
        return None, None, "That username is already taken."
    if email_exists(email):
        return None, None, "That email is already registered."

    master_key = generate_master_key()
    salt = generate_salt()
    pw_key = derive_key(password, salt)
    pw_wrapped = encrypt_bytes(pw_key, master_key)
    server_wrapped = encrypt_bytes(SERVER_KEY, master_key)

    priv_pem, pub_pem = generate_keypair()
    priv_wrapped = encrypt_bytes(master_key, priv_pem)

    with engine.begin() as conn:
        try:
            result = conn.execute(
                users.insert().values(
                    username=username,
                    email=email,
                    salt=b64(salt),
                    pw_wrapped_nonce=pw_wrapped["nonce"],
                    pw_wrapped_ciphertext=pw_wrapped["ciphertext"],
                    server_wrapped_nonce=server_wrapped["nonce"],
                    server_wrapped_ciphertext=server_wrapped["ciphertext"],
                    public_key=pub_pem.decode("utf-8"),
                    priv_wrapped_nonce=priv_wrapped["nonce"],
                    priv_wrapped_ciphertext=priv_wrapped["ciphertext"],
                    created_at=time.time(),
                )
            )
            user_id = result.inserted_primary_key[0]
        except IntegrityError:
            return None, None, "That username or email is already taken."

    return user_id, master_key, None


def login(username: str, password: str):
    """Tries to log in. Returns (user_id, master_key, error)."""
    lockout_error = _check_lockout(username)
    if lockout_error:
        return None, None, lockout_error

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT id, salt, pw_wrapped_nonce, pw_wrapped_ciphertext "
                "FROM users WHERE username = :u"
            ),
            {"u": username},
        ).fetchone()

    success = False
    user_id = None
    master_key = None

    if row is not None:
        user_id, salt_b64, nonce, ct = row
        pw_key = derive_key(password, unb64(salt_b64))
        try:
            master_key = decrypt_bytes(pw_key, nonce, ct)
            success = True
        except Exception:
            success = False

    _record_attempt(username, success)

    if success:
        return user_id, master_key, None
    return None, None, "Incorrect username or password."


# --- Email OTP password reset ----------------------------------------------

def _find_user_by_identifier(identifier: str):
    """Looks a user up by username OR email. Returns a row or None."""
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT id, username, email FROM users "
                "WHERE username = :i OR email = :i"
            ),
            {"i": identifier},
        ).fetchone()


def request_password_reset(identifier: str):
    """Generates and 'sends' an OTP for the account matching this username
    or email. Always returns a generic (ok, message) result regardless of
    whether the account exists, so this can't be used to check which
    usernames/emails are registered.

    Returns (ok, message, dev_otp):
    - ok is True as long as no rate limit was hit (even if the account
      doesn't exist -- we don't reveal that).
    - dev_otp is the plaintext OTP ONLY if email sending isn't configured
      (dev/local mode); otherwise None, since real deployments should
      only reveal the code via email.
    """
    import email_utils

    generic_message = (
        "If that username or email is registered, a reset code has been sent to "
        "the account's email address."
    )

    row = _find_user_by_identifier(identifier)
    if row is None:
        # Don't reveal non-existence -- just pretend it worked.
        return True, generic_message, None

    user_id, username, email = row

    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT created_at FROM otp_codes WHERE username = :u"),
            {"u": username},
        ).fetchone()
    if existing is not None and (time.time() - existing[0]) < OTP_RESEND_COOLDOWN:
        wait = int(OTP_RESEND_COOLDOWN - (time.time() - existing[0]))
        return False, f"Please wait about {wait} second(s) before requesting another code.", None

    otp = generate_otp()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM otp_codes WHERE username = :u"), {"u": username})
        conn.execute(
            otp_codes.insert().values(
                username=username,
                otp_hash=hash_otp(otp),
                expires_at=time.time() + OTP_TTL_SECONDS,
                attempts=0,
                created_at=time.time(),
            )
        )

    if email_utils.is_configured():
        try:
            email_utils.send_otp_email(email, otp)
        except Exception as e:
            return False, f"Could not send the reset email: {e}", None
        return True, generic_message, None
    else:
        # Dev/local fallback: no SMTP configured, so show the code
        # directly instead of emailing it.
        return True, generic_message, otp


def verify_otp_and_reset(identifier: str, otp: str, new_password: str):
    """Verifies an OTP and, if correct, re-wraps the account's master key
    under a new password. Returns (user_id, master_key, error)."""
    row = _find_user_by_identifier(identifier)
    if row is None:
        return None, None, "Incorrect code."
    user_id, username, email = row

    lockout_error = _check_lockout(username)
    if lockout_error:
        return None, None, lockout_error

    with engine.connect() as conn:
        otp_row = conn.execute(
            text("SELECT otp_hash, expires_at, attempts FROM otp_codes WHERE username = :u"),
            {"u": username},
        ).fetchone()

    if otp_row is None:
        return None, None, "No reset code was requested for this account, or it already expired."

    otp_hash, expires_at, attempts = otp_row

    if time.time() > expires_at:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM otp_codes WHERE username = :u"), {"u": username})
        return None, None, "This code has expired. Please request a new one."

    if attempts >= OTP_MAX_ATTEMPTS:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM otp_codes WHERE username = :u"), {"u": username})
        return None, None, "Too many incorrect attempts. Please request a new code."

    if hash_otp(otp.strip()) != otp_hash:
        with engine.begin() as conn:
            conn.execute(
                otp_codes.update().where(otp_codes.c.username == username).values(
                    attempts=attempts + 1
                )
            )
        _record_attempt(username, False)
        return None, None, "Incorrect code."

    # Correct OTP -- unwrap the master key using the server secret.
    with engine.connect() as conn:
        wrap_row = conn.execute(
            text(
                "SELECT server_wrapped_nonce, server_wrapped_ciphertext "
                "FROM users WHERE id = :uid"
            ),
            {"uid": user_id},
        ).fetchone()

    try:
        master_key = decrypt_bytes(SERVER_KEY, wrap_row[0], wrap_row[1])
    except Exception:
        return None, None, "Could not verify this account's stored data. Please contact support."

    # Re-wrap the same master key under the new password + a new salt.
    new_salt = generate_salt()
    new_pw_key = derive_key(new_password, new_salt)
    new_pw_wrapped = encrypt_bytes(new_pw_key, master_key)

    with engine.begin() as conn:
        conn.execute(
            users.update().where(users.c.id == user_id).values(
                salt=b64(new_salt),
                pw_wrapped_nonce=new_pw_wrapped["nonce"],
                pw_wrapped_ciphertext=new_pw_wrapped["ciphertext"],
            )
        )
        conn.execute(text("DELETE FROM otp_codes WHERE username = :u"), {"u": username})

    _record_attempt(username, True)
    return user_id, master_key, None


# --- Notes -------------------------------------------------------------

def load_notes(user_id: int) -> list:
    """Returns every note belonging to this user, each with its history,
    newest note first."""
    with engine.connect() as conn:
        note_rows = conn.execute(
            text(
                "SELECT id, title, folder, current_nonce, current_ciphertext, updated_at "
                "FROM notes WHERE user_id = :uid ORDER BY updated_at DESC"
            ),
            {"uid": user_id},
        ).fetchall()

        result = []
        for nid, title, folder, c_nonce, c_ct, c_ts in note_rows:
            history_rows = conn.execute(
                text(
                    "SELECT id, nonce, ciphertext, timestamp "
                    "FROM note_history WHERE note_id = :nid ORDER BY timestamp ASC"
                ),
                {"nid": nid},
            ).fetchall()
            history = [
                {"history_id": h_id, "nonce": h_nonce, "ciphertext": h_ct, "timestamp": h_ts}
                for h_id, h_nonce, h_ct, h_ts in history_rows
            ]
            result.append({
                "id": nid,
                "title": title,
                "folder": folder or "Uncategorized",
                "current": {"nonce": c_nonce, "ciphertext": c_ct, "timestamp": c_ts},
                "history": history,
            })
        return result


def add_note(user_id: int, master_key: bytes, title: str, content: str, folder: str = None):
    encrypted = encrypt(master_key, content)
    with engine.begin() as conn:
        conn.execute(
            notes.insert().values(
                id=str(uuid.uuid4()),
                user_id=user_id,
                title=title,
                folder=(folder or None),
                current_nonce=encrypted["nonce"],
                current_ciphertext=encrypted["ciphertext"],
                updated_at=time.time(),
            )
        )


def list_folders(user_id: int) -> list:
    """Returns the distinct folder names this user has used, sorted."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT DISTINCT folder FROM notes "
                "WHERE user_id = :uid AND folder IS NOT NULL AND folder != ''"
            ),
            {"uid": user_id},
        ).fetchall()
    return sorted(r[0] for r in rows)


def update_note(master_key: bytes, note_id: str, new_content: str, new_title: str = None, new_folder: str = None):
    """Encrypts the new content, archives the old current version into
    history, and saves the new one as current."""
    with engine.begin() as conn:
        old = conn.execute(
            text(
                "SELECT current_nonce, current_ciphertext, updated_at "
                "FROM notes WHERE id = :nid"
            ),
            {"nid": note_id},
        ).fetchone()
        if old is None:
            return
        old_nonce, old_ct, old_ts = old

        conn.execute(
            note_history.insert().values(
                note_id=note_id, nonce=old_nonce, ciphertext=old_ct, timestamp=old_ts
            )
        )

        encrypted = encrypt(master_key, new_content)
        update_values = {
            "current_nonce": encrypted["nonce"],
            "current_ciphertext": encrypted["ciphertext"],
            "updated_at": time.time(),
        }
        if new_title:
            update_values["title"] = new_title
        if new_folder is not None:
            update_values["folder"] = (new_folder or None)

        conn.execute(
            notes.update().where(notes.c.id == note_id).values(**update_values)
        )


def restore_version(master_key: bytes, note_id: str, history_id: int):
    """Makes an old version current again, and files the replaced version
    back into history so nothing is ever lost."""
    with engine.begin() as conn:
        old_current = conn.execute(
            text(
                "SELECT current_nonce, current_ciphertext, updated_at "
                "FROM notes WHERE id = :nid"
            ),
            {"nid": note_id},
        ).fetchone()
        version = conn.execute(
            text("SELECT nonce, ciphertext, timestamp FROM note_history WHERE id = :hid"),
            {"hid": history_id},
        ).fetchone()
        if old_current is None or version is None:
            return

        conn.execute(
            notes.update().where(notes.c.id == note_id).values(
                current_nonce=version[0],
                current_ciphertext=version[1],
                updated_at=version[2],
            )
        )
        conn.execute(note_history.delete().where(note_history.c.id == history_id))
        conn.execute(
            note_history.insert().values(
                note_id=note_id,
                nonce=old_current[0],
                ciphertext=old_current[1],
                timestamp=old_current[2],
            )
        )


def delete_note(note_id: str):
    with engine.begin() as conn:
        conn.execute(note_history.delete().where(note_history.c.note_id == note_id))
        conn.execute(notes.delete().where(notes.c.id == note_id))


def export_notes(user_id: int) -> dict:
    """Returns this user's notes as a plain dict, ready to be saved as JSON.
    Everything inside stays encrypted -- exporting doesn't decrypt anything."""
    return {"notes": load_notes(user_id)}


def import_notes(user_id: int, data: dict, merge: bool = True) -> int:
    """Imports notes from a previously exported dict. Because notes are
    encrypted with the account's own master key, imported notes only
    display correctly if they were exported from this same account.

    Every imported note gets a brand-new ID rather than reusing the one
    from the export file. Note IDs are unique across the whole database
    (not just per-account), so reusing an ID that already belongs to
    another user's note would collide with it."""
    if not merge:
        with engine.begin() as conn:
            for n in load_notes(user_id):
                conn.execute(note_history.delete().where(note_history.c.note_id == n["id"]))
            conn.execute(notes.delete().where(notes.c.user_id == user_id))

    added = 0
    with engine.begin() as conn:
        for note in data.get("notes", []):
            new_note_id = str(uuid.uuid4())
            conn.execute(
                notes.insert().values(
                    id=new_note_id,
                    user_id=user_id,
                    title=note["title"],
                    current_nonce=note["current"]["nonce"],
                    current_ciphertext=note["current"]["ciphertext"],
                    updated_at=note["current"]["timestamp"],
                )
            )
            for version in note.get("history", []):
                conn.execute(
                    note_history.insert().values(
                        note_id=new_note_id,
                        nonce=version["nonce"],
                        ciphertext=version["ciphertext"],
                        timestamp=version["timestamp"],
                    )
                )
            added += 1
    return added


# --- Sharing notes with other accounts -------------------------------------
# Sharing creates a self-contained encrypted snapshot for the recipient,
# using a fresh one-time AES key that only the recipient's private key can
# unlock. The sender's own key is never exposed to anyone else.

def get_public_key(username: str):
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, public_key FROM users WHERE username = :u"), {"u": username}
        ).fetchone()
    return row  # (user_id, public_key_pem_str) or None


def share_note(owner_user_id: int, owner_master_key: bytes, note_id: str, recipient_username: str):
    """Encrypts a snapshot of a note specifically for the recipient.

    Returns (ok, error). error is a human-readable reason on failure."""
    from crypto_utils import generate_master_key as _gen_key  # reuse: any random 32 bytes

    recipient = get_public_key(recipient_username)
    if recipient is None:
        return False, "No account with that username."
    recipient_user_id, recipient_pub_pem = recipient

    if recipient_user_id == owner_user_id:
        return False, "You can't share a note with yourself."

    with engine.connect() as conn:
        note_row = conn.execute(
            text(
                "SELECT title, current_nonce, current_ciphertext "
                "FROM notes WHERE id = :nid AND user_id = :uid"
            ),
            {"nid": note_id, "uid": owner_user_id},
        ).fetchone()
    if note_row is None:
        return False, "Note not found."
    title, c_nonce, c_ct = note_row

    try:
        plaintext_content = decrypt(owner_master_key, c_nonce, c_ct)
    except Exception:
        return False, "Could not decrypt this note to share it."

    # Fresh one-time key for this share, encrypted for the recipient only.
    share_key = _gen_key()
    wrapped_key = rsa_encrypt(recipient_pub_pem.encode("utf-8"), share_key)

    title_enc = encrypt(share_key, title)
    content_enc = encrypt(share_key, plaintext_content)

    with engine.begin() as conn:
        conn.execute(
            note_shares.insert().values(
                owner_user_id=owner_user_id,
                recipient_user_id=recipient_user_id,
                source_note_id=note_id,
                wrapped_key=b64(wrapped_key),
                title_nonce=title_enc["nonce"],
                title_ciphertext=title_enc["ciphertext"],
                content_nonce=content_enc["nonce"],
                content_ciphertext=content_enc["ciphertext"],
                shared_at=time.time(),
            )
        )
    return True, None


def _unwrap_own_private_key(user_id: int, master_key: bytes) -> bytes:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT priv_wrapped_nonce, priv_wrapped_ciphertext "
                "FROM users WHERE id = :uid"
            ),
            {"uid": user_id},
        ).fetchone()
    return decrypt_bytes(master_key, row[0], row[1])


def list_shared_with_me(user_id: int, master_key: bytes) -> list:
    """Returns every note shared with this user, decrypted using their own
    private key (unwrapped with their master key). Each entry is a plain
    dict with the decrypted title/content already available."""
    private_key_pem = _unwrap_own_private_key(user_id, master_key)

    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT ns.id, u.username, ns.wrapped_key, "
                "ns.title_nonce, ns.title_ciphertext, "
                "ns.content_nonce, ns.content_ciphertext, ns.shared_at "
                "FROM note_shares ns "
                "JOIN users u ON u.id = ns.owner_user_id "
                "WHERE ns.recipient_user_id = :uid "
                "ORDER BY ns.shared_at DESC"
            ),
            {"uid": user_id},
        ).fetchall()

    result = []
    for share_id, owner_username, wrapped_key_b64, t_nonce, t_ct, c_nonce, c_ct, shared_at in rows:
        try:
            share_key = rsa_decrypt(private_key_pem, unb64(wrapped_key_b64))
            title = decrypt(share_key, t_nonce, t_ct)
            content = decrypt(share_key, c_nonce, c_ct)
        except Exception:
            title = "(could not decrypt)"
            content = ""
        result.append({
            "share_id": share_id,
            "from": owner_username,
            "title": title,
            "content": content,
            "shared_at": shared_at,
        })
    return result


def unshare(share_id: int, owner_user_id: int):
    """Revokes a share. Only the original owner can revoke it."""
    with engine.begin() as conn:
        conn.execute(
            note_shares.delete().where(
                (note_shares.c.id == share_id) & (note_shares.c.owner_user_id == owner_user_id)
            )
        )


def list_my_shares(owner_user_id: int) -> list:
    """Returns the shares this user has sent out (for managing/revoking)."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT ns.id, u.username, ns.source_note_id, ns.shared_at "
                "FROM note_shares ns "
                "JOIN users u ON u.id = ns.recipient_user_id "
                "WHERE ns.owner_user_id = :uid "
                "ORDER BY ns.shared_at DESC"
            ),
            {"uid": owner_user_id},
        ).fetchall()
    return [
        {"share_id": r[0], "recipient": r[1], "source_note_id": r[2], "shared_at": r[3]}
        for r in rows
    ]


# --- Biometric login (WebAuthn / passkeys) ---------------------------------
# See webauthn_utils.py for the cryptographic verification logic and the
# security-model explanation. This section just stores/retrieves
# credentials and, on a successful verification, unwraps the account's
# master key using the SAME server-escrow key already used for email/OTP
# password reset -- so this doesn't introduce a new weakening of the
# security model, it reuses the one already made and documented there.

def add_credential(user_id: int, credential_id: str, public_key: bytes, sign_count: int, nickname: str):
    with engine.begin() as conn:
        conn.execute(
            webauthn_credentials.insert().values(
                user_id=user_id,
                credential_id=credential_id,
                public_key=b64(public_key),
                sign_count=sign_count,
                nickname=nickname,
                created_at=time.time(),
            )
        )


def list_credentials(user_id: int) -> list:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT id, credential_id, nickname, created_at "
                "FROM webauthn_credentials WHERE user_id = :uid ORDER BY created_at DESC"
            ),
            {"uid": user_id},
        ).fetchall()
    return [
        {"id": r[0], "credential_id": r[1], "nickname": r[2], "created_at": r[3]}
        for r in rows
    ]


def get_credential_ids_for_user(user_id: int) -> list:
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT credential_id FROM webauthn_credentials WHERE user_id = :uid"),
            {"uid": user_id},
        ).fetchall()
    return [r[0] for r in rows]


def get_credential_ids_for_username(username: str) -> list:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT wc.credential_id FROM webauthn_credentials wc "
                "JOIN users u ON u.id = wc.user_id WHERE u.username = :u"
            ),
            {"u": username},
        ).fetchall()
    return [r[0] for r in rows]


def delete_credential(credential_row_id: int, user_id: int):
    """Only removes it if it actually belongs to this user."""
    with engine.begin() as conn:
        conn.execute(
            webauthn_credentials.delete().where(
                (webauthn_credentials.c.id == credential_row_id)
                & (webauthn_credentials.c.user_id == user_id)
            )
        )


def get_credential_for_verification(credential_id: str):
    """Returns (user_id, public_key_bytes, sign_count) for a given
    credential_id, or None if it's not registered to anyone."""
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT user_id, public_key, sign_count FROM webauthn_credentials "
                "WHERE credential_id = :cid"
            ),
            {"cid": credential_id},
        ).fetchone()
    if row is None:
        return None
    return row[0], unb64(row[1]), row[2]


def update_credential_sign_count(credential_id: str, new_sign_count: int):
    with engine.begin() as conn:
        conn.execute(
            webauthn_credentials.update()
            .where(webauthn_credentials.c.credential_id == credential_id)
            .values(sign_count=new_sign_count)
        )


def biometric_login(username: str, credential_id: str, verified_sign_count: int):
    """Called AFTER webauthn_utils.verify_authentication() has already
    cryptographically confirmed the passkey signature is valid for this
    credential. This function's job is just to: confirm the credential
    actually belongs to the claimed username, update its sign count, and
    unwrap the master key via the server escrow key so the app can log
    the user in -- exactly like the email/OTP path does, minus changing
    the password.

    Returns (user_id, master_key, error)."""
    lockout_error = _check_lockout(username)
    if lockout_error:
        return None, None, lockout_error

    row = _find_user_by_identifier(username)
    if row is None:
        _record_attempt(username, False)
        return None, None, "Account not found."
    user_id, db_username, email = row

    cred_info = get_credential_for_verification(credential_id)
    if cred_info is None or cred_info[0] != user_id:
        _record_attempt(username, False)
        return None, None, "This passkey is not registered to this account."

    update_credential_sign_count(credential_id, verified_sign_count)

    with engine.connect() as conn:
        wrap_row = conn.execute(
            text(
                "SELECT server_wrapped_nonce, server_wrapped_ciphertext "
                "FROM users WHERE id = :uid"
            ),
            {"uid": user_id},
        ).fetchone()

    try:
        master_key = decrypt_bytes(SERVER_KEY, wrap_row[0], wrap_row[1])
    except Exception:
        _record_attempt(username, False)
        return None, None, "Could not unlock this account's data."

    _record_attempt(username, True)
    return user_id, master_key, None