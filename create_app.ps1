$path = "C:\Users\sirid\secure-notes-app\app.py"
$content = @'
"""
app.py
------
Streamlit front-end for Secure Notes (multi-user, with email/OTP password
reset).

Run it with:
    streamlit run app.py
"""

from datetime import datetime

import streamlit as st

import db
from crypto_utils import decrypt as _decrypt

st.set_page_config(page_title="Secure Notes", page_icon=":lock:", layout="wide")
db.init_db()

# --- Session state defaults --------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "username" not in st.session_state:
    st.session_state.username = None
if "key" not in st.session_state:
    st.session_state.key = None
if "selected_note_id" not in st.session_state:
    st.session_state.selected_note_id = None
if "otp_requested_for" not in st.session_state:
    # Tracks which account (username/email) currently has a pending OTP,
    # so the "Forgot password" tab can move from "request a code" to
    # "enter the code" without losing that context on rerun.
    st.session_state.otp_requested_for = None
if "dev_otp_hint" not in st.session_state:
    # Only ever set when SMTP isn't configured (local dev/testing), so
    # the OTP can be shown on screen instead of emailed.
    st.session_state.dev_otp_hint = None


def log_out():
    """Wipes the encryption key and session from memory. The key never
    touches disk, so this is all it takes to fully lock the account."""
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = None
    st.session_state.key = None
    st.session_state.selected_note_id = None


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


# =========================================================================
# SCREEN 1 -- Not logged in: sign up, log in, or reset a forgotten password
# =========================================================================
if not st.session_state.logged_in:
    st.title("Secure Notes")
    st.write("An encrypted notes app. Each account has its own password and its own key - nobody else can read your notes, including us.")

    tab_login, tab_signup, tab_forgot = st.tabs(["Log in", "Sign up", "Forgot password"])

    with tab_login:
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Log in")

        if submitted:
            user_id, key, error = db.login(username.strip(), password)
            if error:
                st.error(error)
            else:
                st.session_state.logged_in = True
                st.session_state.user_id = user_id
                st.session_state.username = username.strip()
                st.session_state.key = key
                st.rerun()

    with tab_signup:
        with st.form("signup_form"):
            new_username = st.text_input("Choose a username", key="signup_username")
            new_email = st.text_input("Email address", key="signup_email")
            pw1 = st.text_input("Choose a password", type="password", key="signup_pw1")
            pw2 = st.text_input("Confirm password", type="password", key="signup_pw2")
            submitted = st.form_submit_button("Create account")

        if submitted:
            new_username = new_username.strip()
            new_email = new_email.strip()
            if len(new_username) < 3:
                st.error("Username must be at least 3 characters.")
            elif "@" not in new_email or "." not in new_email:
                st.error("Please enter a valid email address.")
            elif len(pw1) < 8:
                st.error("Password must be at least 8 characters.")
            elif pw1 != pw2:
                st.error("Passwords don't match.")
            else:
                user_id, key, error = db.create_user(new_username, new_email, pw1)
                if error:
                    st.error(error)
                else:
                    st.session_state.logged_in = True
                    st.session_state.user_id = user_id
                    st.session_state.username = new_username
                    st.session_state.key = key
                    st.rerun()

    with tab_forgot:
        st.write(
            "Enter your username or email to receive a one-time code. "
            "Entering it correctly lets you set a new password - your "
            "existing notes will still be there afterward."
        )

        if st.session_state.otp_requested_for is None:
            # --- Step 1: request a code ---
            with st.form("request_otp_form"):
                identifier = st.text_input("Username or email", key="forgot_identifier")
                submitted = st.form_submit_button("Send code")

            if submitted:
                if not identifier.strip():
                    st.error("Please enter your username or email.")
                else:
                    ok, message, dev_otp = db.request_password_reset(identifier.strip())
                    if not ok:
                        st.error(message)
                    else:
                        st.session_state.otp_requested_for = identifier.strip()
                        st.session_state.dev_otp_hint = dev_otp
                        st.rerun()

        else:
            # --- Step 2: enter the code + new password ---
            st.info(f"A code has been requested for: {st.session_state.otp_requested_for}")
            if st.session_state.dev_otp_hint:
                st.warning(
                    "DEV MODE (no email server configured): your code is "
                    f"**{st.session_state.dev_otp_hint}** - shown here instead of "
                    "emailed. Configure SMTP before deploying for real; see README."
                )

            with st.form("verify_otp_form"):
                otp_input = st.text_input("6-digit code", key="otp_input")
                new_pw1 = st.text_input("New password", type="password", key="reset_pw1")
                new_pw2 = st.text_input("Confirm new password", type="password", key="reset_pw2")
                col1, col2 = st.columns(2)
                with col1:
                    submitted = st.form_submit_button("Reset password")
                with col2:
                    start_over = st.form_submit_button("Start over / use a different account")

            if start_over:
                st.session_state.otp_requested_for = None
                st.session_state.dev_otp_hint = None
                st.rerun()

            if submitted:
                if len(new_pw1) < 8:
                    st.error("New password must be at least 8 characters.")
                elif new_pw1 != new_pw2:
                    st.error("Passwords don't match.")
                elif not otp_input.strip():
                    st.error("Please enter the code.")
                else:
                    user_id, key, error = db.verify_otp_and_reset(
                        st.session_state.otp_requested_for, otp_input.strip(), new_pw1
                    )
                    if error:
                        st.error(error)
                    else:
                        st.session_state.otp_requested_for = None
                        st.session_state.dev_otp_hint = None
                        st.session_state.logged_in = True
                        st.session_state.user_id = user_id
                        st.session_state.username = db.get_username(user_id)
                        st.session_state.key = key
                        st.success("Password reset. You're logged in.")
                        st.rerun()

    st.caption("Forgot passwords are reset using a one-time code sent to your registered email.")

# =========================================================================
# SCREEN 2 -- Logged in: the actual app
# =========================================================================
else:
    key = st.session_state.key
    user_id = st.session_state.user_id

    # --- Sidebar: account info, note list, log out ------------------------
    with st.sidebar:
        st.title("Secure Notes")
        st.caption(f"Logged in as **{st.session_state.username}**")
        if st.button("Log out", use_container_width=True):
            log_out()
            st.rerun()

        st.divider()
        st.subheader("Your notes")

        user_notes = db.load_notes(user_id)

        if st.button("New note", use_container_width=True):
            st.session_state.selected_note_id = "__new__"

        for note in user_notes:
            label = note["title"] or "(untitled)"
            if st.button(label, key=f"select_{note['id']}", use_container_width=True):
                st.session_state.selected_note_id = note["id"]

    # --- Main area: tabs ---------------------------------------------------
    tab_notes, tab_io, tab_bio = st.tabs(["Notes", "Import / Export", "Biometric"])

    # ---------------- NOTES TAB ----------------
    with tab_notes:
        selected = st.session_state.selected_note_id

        if selected is None:
            st.info("Select a note from the sidebar, or create a new one.")

        elif selected == "__new__":
            st.subheader("New note")
            title = st.text_input("Title", key="new_title")
            content = st.text_area("Content", height=300, key="new_content")
            if st.button("Save note"):
                if not title.strip():
                    st.error("Please give the note a title.")
                else:
                    db.add_note(user_id, key, title.strip(), content)
                    st.success("Note saved.")
                    st.session_state.selected_note_id = None
                    st.rerun()

        else:
            user_notes = db.load_notes(user_id)
            note = next((n for n in user_notes if n["id"] == selected), None)

            if note is None:
                st.warning("That note no longer exists.")
                st.session_state.selected_note_id = None
            else:
                current_text = _decrypt(
                    key, note["current"]["nonce"], note["current"]["ciphertext"]
                )

                st.subheader(f"Editing: {note['title']}")
                new_title = st.text_input("Title", value=note["title"], key=f"title_{note['id']}")
                new_content = st.text_area(
                    "Content", value=current_text, height=300, key=f"content_{note['id']}"
                )

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Save changes"):
                        db.update_note(key, note["id"], new_content, new_title.strip())
                        st.success("Saved. Previous version kept in history.")
                        st.rerun()
                with col2:
                    if st.button("Delete note"):
                        db.delete_note(note["id"])
                        st.session_state.selected_note_id = None
                        st.success("Note deleted.")
                        st.rerun()

                # --- Version history ---
                st.divider()
                st.subheader("Version history")
                if not note["history"]:
                    st.caption("No previous versions yet - edit and save to create one.")
                else:
                    for version in reversed(note["history"]):
                        with st.expander(f"Version from {fmt_time(version['timestamp'])}"):
                            old_text = _decrypt(key, version["nonce"], version["ciphertext"])
                            st.text(old_text)
                            if st.button("Restore this version", key=f"restore_{version['history_id']}"):
                                db.restore_version(key, note["id"], version["history_id"])
                                st.success("Version restored.")
                                st.rerun()

    # ---------------- IMPORT / EXPORT TAB ----------------
    with tab_io:
        st.subheader("Export your notes")
        st.write(
            "Exports every note in its encrypted form. The file is safe to "
            "back up or share - it's useless without your password, and it "
            "will only decrypt correctly when imported back into this same account."
        )
        export_data = db.export_notes(user_id)
        export_json = __import__("json").dumps(export_data, indent=2)
        st.download_button(
            "Download encrypted backup (notes_export.json)",
            data=export_json,
            file_name="notes_export.json",
            mime="application/json",
        )

        st.divider()
        st.subheader("Import notes")
        st.write("Upload a backup previously exported from this same account.")
        uploaded = st.file_uploader("Choose a backup file", type="json")
        merge_mode = st.radio(
            "Import mode",
            ["Merge with existing notes", "Replace all existing notes"],
        )
        if uploaded is not None and st.button("Import now"):
            import json as _json
            try:
                imported = _json.loads(uploaded.getvalue().decode("utf-8"))
                merge = merge_mode == "Merge with existing notes"
                count = db.import_notes(user_id, imported, merge=merge)
                st.success(f"Imported {count} note(s).")
                st.rerun()
            except Exception as e:
                st.error(f"Could not import this file: {e}")

    # ---------------- BIOMETRIC TAB (placeholder) ----------------
    with tab_bio:
        st.subheader("Windows Biometric Unlock")
        st.info(
            "Placeholder - not yet implemented.\n\n"
            "The plan is to let Windows Hello (fingerprint or face "
            "recognition) unlock the app instead of typing a password, "
            "using the Windows Hello / Windows Biometric Framework APIs. "
            "This only makes sense when running the app locally on "
            "Windows - it won't apply to the hosted/deployed version."
        )
        st.checkbox("Enable Windows Hello unlock (coming soon)", value=False, disabled=True)
'@
[System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Created $path"