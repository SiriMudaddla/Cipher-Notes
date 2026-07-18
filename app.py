"""
app.py
------
Streamlit front-end for CipherNotes (multi-user, encrypted, with email/OTP
password reset, folders, and note sharing).

Run it with:
    streamlit run app.py
"""

from datetime import datetime

import streamlit as st

import db
import webauthn_utils
from webauthn_bridge import webauthn_prompt
from webauthn.helpers import options_to_json, bytes_to_base64url
from crypto_utils import decrypt as _decrypt

st.set_page_config(page_title="CipherNotes", page_icon=":lock:", layout="wide")
db.init_db()

# --- Styling -------------------------------------------------------------
# Font + centered headings only. Deliberately no background/text colors
# here -- Streamlit's built-in light/dark toggle (menu -> Settings) works
# by swapping its own theme variables, and hardcoding a color here would
# lock the app to one mode regardless of that toggle. Headings need an
# explicit font-family rule of their own -- Streamlit sets one directly on
# h1/h2/etc, so relying on inheritance from html/body alone doesn't reach
# them.
st.markdown(
    """
    <style>
    html, body, [class*="css"],
    h1, h2, h3, h4, h5, h6 {
        font-family: "Times New Roman", Times, serif !important;
    }
    h1 {
        text-align: center;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

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
    st.title("CipherNotes")
    st.write("An encrypted notes app. Each account has its own password and its own key - nobody else can read your notes, including us, unless you explicitly share one.")

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

        st.divider()
        st.caption("Or use a registered device (Windows Hello, Touch ID, Face ID):")
        bio_username = st.text_input("Username (for biometric login)", key="bio_login_username")

        if bio_username.strip():
            cred_ids = db.get_credential_ids_for_username(bio_username.strip())
            if not cred_ids:
                st.caption("No passkey registered for this username yet.")
            else:
                auth_options = webauthn_utils.build_authentication_options(cred_ids)
                auth_options_json = options_to_json(auth_options)
                st.session_state["_pending_auth_challenge"] = bytes_to_base64url(auth_options.challenge)

                bio_result = webauthn_prompt(
                    "authenticate", auth_options_json, key="login_passkey_widget"
                )
                if bio_result.result:
                    payload = bio_result.result
                    if payload.get("error"):
                        st.error(f"Biometric login failed: {payload['error']}")
                    else:
                        try:
                            import json as _json
                            cred_json = _json.dumps(payload["credential"])
                            cred_id = payload["credential"]["id"]
                            cred_info = db.get_credential_for_verification(cred_id)
                            if cred_info is None:
                                st.error("This passkey is not recognized.")
                            else:
                                _, stored_pub_key, stored_sign_count = cred_info
                                new_sign_count = webauthn_utils.verify_authentication(
                                    cred_json,
                                    st.session_state["_pending_auth_challenge"],
                                    stored_pub_key,
                                    stored_sign_count,
                                )
                                login_uid, login_key, login_err = db.biometric_login(
                                    bio_username.strip(), cred_id, new_sign_count
                                )
                                if login_err:
                                    st.error(login_err)
                                else:
                                    st.session_state.logged_in = True
                                    st.session_state.user_id = login_uid
                                    st.session_state.username = db.get_username(login_uid)
                                    st.session_state.key = login_key
                                    st.rerun()
                        except Exception as e:
                            st.error(f"Could not verify this device: {e}")

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

    # --- Sidebar: account info, folders/notes, log out ---------------------
    with st.sidebar:
        st.title("CipherNotes")
        st.caption(f"Logged in as **{st.session_state.username}**")
        if st.button("Log out", use_container_width=True):
            log_out()
            st.rerun()

        st.divider()
        st.subheader("Your notes")

        user_notes = db.load_notes(user_id)

        if st.button("New note", use_container_width=True):
            st.session_state.selected_note_id = "__new__"

        # Group notes by folder, "Uncategorized" last.
        by_folder = {}
        for note in user_notes:
            by_folder.setdefault(note["folder"], []).append(note)
        folder_names = sorted(f for f in by_folder if f != "Uncategorized")
        if "Uncategorized" in by_folder:
            folder_names.append("Uncategorized")

        for folder_name in folder_names:
            with st.expander(folder_name, expanded=True):
                for note in by_folder[folder_name]:
                    label = note["title"] or "(untitled)"
                    if st.button(label, key=f"select_{note['id']}", use_container_width=True):
                        st.session_state.selected_note_id = note["id"]

    # --- Main area: tabs ---------------------------------------------------
    tab_notes, tab_shared, tab_io, tab_bio = st.tabs(
        ["Notes", "Shared with me", "Import / Export", "Biometric"]
    )

    # ---------------- NOTES TAB ----------------
    with tab_notes:
        selected = st.session_state.selected_note_id

        if selected is None:
            st.info("Select a note from the sidebar, or create a new one.")

        elif selected == "__new__":
            st.subheader("New note")
            title = st.text_input("Title", key="new_title")
            existing_folders = db.list_folders(user_id)
            folder_choice = st.selectbox(
                "Folder", ["(none)"] + existing_folders + ["+ New folder..."], key="new_folder_choice"
            )
            if folder_choice == "+ New folder...":
                folder_value = st.text_input("New folder name", key="new_folder_name").strip()
            elif folder_choice == "(none)":
                folder_value = None
            else:
                folder_value = folder_choice
            content = st.text_area("Content", height=300, key="new_content")
            if st.button("Save note"):
                if not title.strip():
                    st.error("Please give the note a title.")
                else:
                    db.add_note(user_id, key, title.strip(), content, folder=folder_value)
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

                existing_folders = db.list_folders(user_id)
                options = ["(none)"] + existing_folders + ["+ New folder..."]
                current_folder = note["folder"] if note["folder"] != "Uncategorized" else "(none)"
                default_index = options.index(current_folder) if current_folder in options else 0
                folder_choice = st.selectbox(
                    "Folder", options, index=default_index, key=f"folder_{note['id']}"
                )
                if folder_choice == "+ New folder...":
                    new_folder_value = st.text_input("New folder name", key=f"newfolder_{note['id']}").strip()
                elif folder_choice == "(none)":
                    new_folder_value = ""
                else:
                    new_folder_value = folder_choice

                new_content = st.text_area(
                    "Content", value=current_text, height=300, key=f"content_{note['id']}"
                )

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Save changes"):
                        db.update_note(
                            key, note["id"], new_content, new_title.strip(), new_folder=new_folder_value
                        )
                        st.success("Saved. Previous version kept in history.")
                        st.rerun()
                with col2:
                    if st.button("Delete note"):
                        db.delete_note(note["id"])
                        st.session_state.selected_note_id = None
                        st.success("Note deleted.")
                        st.rerun()

                # --- Share with another account ---
                st.divider()
                st.subheader("Share with another account")
                st.caption(
                    "Creates an encrypted copy specifically for that person, using their "
                    "public key. They see a snapshot as of right now - editing this note "
                    "afterward won't change what they see unless you share it again."
                )
                with st.form(f"share_form_{note['id']}"):
                    recipient = st.text_input("Their username", key=f"recipient_{note['id']}")
                    share_submitted = st.form_submit_button("Share")
                if share_submitted:
                    if not recipient.strip():
                        st.error("Enter a username to share with.")
                    else:
                        ok, error = db.share_note(user_id, key, note["id"], recipient.strip())
                        if ok:
                            st.success(f"Shared with {recipient.strip()}.")
                        else:
                            st.error(error)

                my_shares = [s for s in db.list_my_shares(user_id) if s["source_note_id"] == note["id"]]
                if my_shares:
                    st.caption("Currently shared with:")
                    for s in my_shares:
                        c1, c2 = st.columns([4, 1])
                        with c1:
                            st.write(f"{s['recipient']} - shared {fmt_time(s['shared_at'])}")
                        with c2:
                            if st.button("Revoke", key=f"revoke_{s['share_id']}"):
                                db.unshare(s["share_id"], user_id)
                                st.rerun()

                # --- Share externally (WhatsApp / Instagram) ---
                st.divider()
                st.subheader("Share externally (WhatsApp / Instagram)")
                st.warning(
                    "This sends the note as plain, unencrypted text through that app - "
                    "unlike sharing within CipherNotes above, this leaves the note's "
                    "encryption entirely once it's sent. Only use this for content "
                    "you're fine having outside CipherNotes."
                )
                import urllib.parse as _urllib_parse
                share_text = f"{note['title']}\n\n{current_text}"
                whatsapp_url = "https://wa.me/?text=" + _urllib_parse.quote(share_text)
                st.link_button("Share via WhatsApp", whatsapp_url)

                st.caption(
                    "Instagram doesn't offer a way to pre-fill message text from a "
                    "website the way WhatsApp does. Copy the note below, then open "
                    "Instagram and paste it into a DM yourself."
                )
                st.code(share_text, language=None)
                st.link_button("Open Instagram", "https://www.instagram.com/direct/inbox/")

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

    # ---------------- SHARED WITH ME TAB ----------------
    with tab_shared:
        st.subheader("Notes shared with you")
        shared_notes = db.list_shared_with_me(user_id, key)
        if not shared_notes:
            st.info("Nobody has shared a note with you yet.")
        else:
            for s in shared_notes:
                with st.expander(f"{s['title']}  -  from {s['from']}  -  {fmt_time(s['shared_at'])}"):
                    st.text(s["content"])

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

    # ---------------- BIOMETRIC TAB ----------------
    with tab_bio:
        st.subheader("Biometric login (passkeys)")
        st.write(
            "Register this device to unlock CipherNotes with Windows Hello, "
            "Touch ID, Face ID, or your device's screen lock instead of "
            "typing your password. This uses WebAuthn, the same standard "
            "browsers use for passkeys - it works the same way across "
            "Windows and Apple devices."
        )
        st.caption(
            "Note: a passkey is tied to the exact domain you register it on. "
            "One registered on localhost during testing won't carry over to "
            "a deployed URL - you'll need to register again there."
        )

        existing = db.list_credentials(user_id)
        if existing:
            st.write("Registered devices:")
            for cred in existing:
                c1, c2 = st.columns([4, 1])
                with c1:
                    st.write(f"{cred['nickname']} - added {fmt_time(cred['created_at'])}")
                with c2:
                    if st.button("Remove", key=f"remove_cred_{cred['id']}"):
                        db.delete_credential(cred["id"], user_id)
                        st.rerun()
        else:
            st.caption("No devices registered yet.")

        st.divider()
        st.write("Register this device:")
        nickname = st.text_input("Name this device (e.g. \"My Laptop\", \"iPhone\")", key="new_device_nickname")

        if nickname.strip():
            reg_options = webauthn_utils.build_registration_options(
                user_id, st.session_state.username, db.get_credential_ids_for_user(user_id)
            )
            reg_options_json = options_to_json(reg_options)
            st.session_state["_pending_reg_challenge"] = bytes_to_base64url(reg_options.challenge)

            result = webauthn_prompt(
                "register", reg_options_json, key="register_passkey_widget"
            )
            if result.result:
                payload = result.result
                if payload.get("error"):
                    st.error(f"Registration failed: {payload['error']}")
                else:
                    try:
                        import json as _json
                        cred_json = _json.dumps(payload["credential"])
                        cred_id, pub_key, sign_count = webauthn_utils.verify_registration(
                            cred_json, st.session_state["_pending_reg_challenge"]
                        )
                        db.add_credential(user_id, cred_id, pub_key, sign_count, nickname.strip())
                        st.success(f"'{nickname.strip()}' registered.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Could not verify this device: {e}")
        else:
            st.caption("Enter a name for this device above to start registration.")
