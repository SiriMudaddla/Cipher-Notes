"""
db.py
-----
Multi-user storage for Secure Notes, built on SQLAlchemy so the exact same
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
    Column("created_at", Float, nullable=False),
)

notes = Table(
    "notes", metadata,
    Column("id", String(36), primary_key=True),
    Column("user_id", Integer, nullable=False),
    Column("title", Text, nullable=False),
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
                "SELECT id, title, current_nonce, current_ciphertext, updated_at "
                "FROM notes WHERE user_id = :uid ORDER BY updated_at DESC"
            ),
            {"uid": user_id},
        ).fetchall()

        result = []
        for nid, title, c_nonce, c_ct, c_ts in note_rows:
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
                "current": {"nonce": c_nonce, "ciphertext": c_ct, "timestamp": c_ts},
                "history": history,
            })
        return result


def add_note(user_id: int, master_key: bytes, title: str, content: str):
    encrypted = encrypt(master_key, content)
    with engine.begin() as conn:
        conn.execute(
            notes.insert().values(
                id=str(uuid.uuid4()),
                user_id=user_id,
                title=title,
                current_nonce=encrypted["nonce"],
                current_ciphertext=encrypted["ciphertext"],
                updated_at=time.time(),
            )
        )


def update_note(master_key: bytes, note_id: str, new_content: str, new_title: str = None):
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