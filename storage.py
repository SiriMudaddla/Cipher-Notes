"""
storage.py
----------
Everything related to reading and writing local files:

- keystore.json  : the salt for your password, plus a small "verifier" blob
                    that lets us check your password is correct WITHOUT
                    ever storing the password itself.
- notes.json     : every note, fully encrypted, plus its version history.

Nothing in either file is readable without the correct password.
"""

import json
import os
import time
import uuid

from crypto_utils import generate_salt, derive_key, encrypt, decrypt, b64, unb64

DATA_DIR = "secure_notes_data"
KEYSTORE_FILE = os.path.join(DATA_DIR, "keystore.json")
NOTES_FILE = os.path.join(DATA_DIR, "notes.json")

# A known piece of text we encrypt at setup time. If decrypting it with a
# freshly-typed password gives back this exact text, the password is right.
VERIFIER_TEXT = "secure-notes-verifier-v1"


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def keystore_exists() -> bool:
    return os.path.exists(KEYSTORE_FILE)


def create_keystore(password: str) -> bytes:
    """First-time setup: makes a new salt, derives a key from the chosen
    password, and stores a verifier so future unlocks can check the
    password. Returns the derived key so the caller can use it right away."""
    ensure_data_dir()
    salt = generate_salt()
    key = derive_key(password, salt)
    verifier = encrypt(key, VERIFIER_TEXT)

    keystore = {
        "salt": b64(salt),
        "verifier_nonce": verifier["nonce"],
        "verifier_ciphertext": verifier["ciphertext"],
    }
    with open(KEYSTORE_FILE, "w") as f:
        json.dump(keystore, f, indent=2)

    if not os.path.exists(NOTES_FILE):
        save_notes({"notes": []})

    return key


def unlock(password: str):
    """Tries to unlock with the given password.
    Returns the derived AES key if correct, otherwise None."""
    with open(KEYSTORE_FILE, "r") as f:
        keystore = json.load(f)

    salt = unb64(keystore["salt"])
    key = derive_key(password, salt)

    try:
        result = decrypt(key, keystore["verifier_nonce"], keystore["verifier_ciphertext"])
        if result == VERIFIER_TEXT:
            return key
    except Exception:
        # Wrong password almost always shows up as a decryption failure here.
        pass
    return None


def load_notes() -> dict:
    if not os.path.exists(NOTES_FILE):
        return {"notes": []}
    with open(NOTES_FILE, "r") as f:
        return json.load(f)


def save_notes(data: dict):
    ensure_data_dir()
    with open(NOTES_FILE, "w") as f:
        json.dump(data, f, indent=2)


def add_note(key: bytes, title: str, content: str):
    data = load_notes()
    encrypted = encrypt(key, content)
    note = {
        "id": str(uuid.uuid4()),
        "title": title,
        "current": {**encrypted, "timestamp": time.time()},
        "history": [],
    }
    data["notes"].append(note)
    save_notes(data)


def update_note(key: bytes, note_id: str, new_content: str, new_title: str = None):
    """Encrypts the new content with a fresh nonce, moves the old version
    into history, and saves the new one as current. Nothing is overwritten
    or lost -- every past version stays available."""
    data = load_notes()
    for note in data["notes"]:
        if note["id"] == note_id:
            note["history"].append(note["current"])
            encrypted = encrypt(key, new_content)
            note["current"] = {**encrypted, "timestamp": time.time()}
            if new_title:
                note["title"] = new_title
            break
    save_notes(data)


def restore_version(key: bytes, note_id: str, history_index: int):
    """Makes an old version current again. The version it replaces is kept
    in history too, so restoring is always reversible."""
    data = load_notes()
    for note in data["notes"]:
        if note["id"] == note_id:
            old_current = note["current"]
            restored = note["history"][history_index]
            note["current"] = restored
            note["history"].append(old_current)
            del note["history"][history_index]
            break
    save_notes(data)


def delete_note(note_id: str):
    data = load_notes()
    data["notes"] = [n for n in data["notes"] if n["id"] != note_id]
    save_notes(data)


def export_notes(export_path: str):
    """Copies the (still fully encrypted) notes file to a chosen location."""
    data = load_notes()
    with open(export_path, "w") as f:
        json.dump(data, f, indent=2)


def import_notes(import_path: str, merge: bool = True):
    """Loads notes from a previously exported JSON file.
    merge=True adds any notes not already present; merge=False replaces
    everything currently stored."""
    with open(import_path, "r") as f:
        imported = json.load(f)

    if merge:
        data = load_notes()
        existing_ids = {n["id"] for n in data["notes"]}
        added = 0
        for note in imported.get("notes", []):
            if note["id"] not in existing_ids:
                data["notes"].append(note)
                added += 1
        save_notes(data)
        return added
    else:
        save_notes(imported)
        return len(imported.get("notes", []))