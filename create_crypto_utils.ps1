"""
crypto_utils.py
----------------
All the cryptography for CipherNotes lives here.

How it works, in plain terms:
1. Every account gets one random "master key" -- this is the key that
   actually encrypts and decrypts your notes. It's generated once and
   never changes.
2. The master key itself is never stored in plain form. Instead it's
   "wrapped" (encrypted) twice, independently:
   - once under a key derived from your password (via PBKDF2-HMAC-SHA256)
   - once under a key derived from the server's own secret
   Your password unwraps the master key for normal logins. The
   server-secret-wrapped copy exists so that a "forgot password" email
   flow can reset your password without losing access to your notes --
   see the note in the "Email OTP password reset" section below about
   what that trade-off means.
3. AES-GCM is used for all encryption here (wrapping the master key,
   and encrypting note content). Every single encryption uses a brand
   new random nonce, so the same input never produces the same output
   twice, and any tampering is detected automatically.
"""

import os
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Tunable constants -------------------------------------------------
PBKDF2_ITERATIONS = 390_000   # higher = slower to brute force, slower to unlock
SALT_SIZE = 16                # bytes, used once per account
NONCE_SIZE = 12               # bytes, standard size for AES-GCM nonces
KEY_SIZE = 32                 # 32 bytes = 256-bit AES key


def generate_salt() -> bytes:
    """A random salt, generated once per account."""
    return os.urandom(SALT_SIZE)


def generate_nonce() -> bytes:
    """A random nonce, generated fresh every time we encrypt something."""
    return os.urandom(NONCE_SIZE)


def generate_master_key() -> bytes:
    """The key that actually encrypts/decrypts note content. Generated
    once per account and never derived from anything -- this is what lets
    it be unlocked by two independent things (password or recovery code)
    without ever needing to re-encrypt notes."""
    return os.urandom(KEY_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """Turns a password + salt into a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(key: bytes, plaintext: str) -> dict:
    """Encrypts text with AES-GCM using a fresh random nonce.
    Returns base64 strings so the result is easy to store as JSON."""
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return {"nonce": b64(nonce), "ciphertext": b64(ciphertext)}


def decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str) -> str:
    """Decrypts AES-GCM ciphertext back to text.
    Raises an exception automatically if the key is wrong, or if the data
    was tampered with -- that's the built-in integrity check GCM gives us
    for free."""
    nonce = unb64(nonce_b64)
    ciphertext = unb64(ciphertext_b64)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def encrypt_bytes(key: bytes, data: bytes) -> dict:
    """Same as encrypt(), but for raw bytes -- used to wrap the master key
    under a password-derived key or a recovery key."""
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return {"nonce": b64(nonce), "ciphertext": b64(ciphertext)}


def decrypt_bytes(key: bytes, nonce_b64: str, ciphertext_b64: str) -> bytes:
    """Same as decrypt(), but returns raw bytes instead of text."""
    nonce = unb64(nonce_b64)
    ciphertext = unb64(ciphertext_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


# --- Email OTP password reset ---------------------------------------------
# Instead of (or alongside) a user-held recovery code, an account's master
# key can also be wrapped under a key derived from a server-side secret.
# When a password reset is requested, a one-time code (OTP) is emailed to
# the account's registered address; entering it correctly proves control
# of that inbox, and the server uses its own secret to unwrap and re-wrap
# the master key under the new password.
#
# Important trade-off: this means the server (whoever holds the secret
# and the database) has enough information to decrypt any account's notes
# on its own, without the user's password. That's different from a
# recovery code, which only the user holds. It's the same trade-off most
# "reset via email" features make.

def generate_otp() -> str:
    """A random 6-digit one-time code."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp: str) -> str:
    """We only ever store a hash of the OTP, never the code itself."""
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def server_key_from_secret(secret: str) -> bytes:
    """Turns the server's own secret string into a 256-bit AES key, used
    to wrap/unwrap master keys for the email-OTP reset path."""
    return hashlib.sha256(secret.encode("utf-8")).digest()


# --- Per-user keypairs (for sharing notes with other accounts) -----------
# Sharing an AES-GCM-encrypted note with another account can't just flip a
# "visible" flag -- the note is only decryptable with the owner's own key,
# which nobody else has or should have. Instead, every account also gets
# an RSA keypair at signup. To share a note with someone, we generate a
# fresh one-time AES key, encrypt a copy of the note with it, and then
# encrypt THAT key with the recipient's public key. Only their matching
# private key (unlocked by their own password, same
