"""
webauthn_utils.py
------------------
Server-side WebAuthn (passkey) logic. This is the real, standard way to
do biometric login on the web -- it's not "Windows Hello" or "Apple
Touch ID" specifically, it's ONE protocol that the browser routes to
whatever platform authenticator the device has (Windows Hello, Touch ID,
Face ID, Android biometrics, etc.). The app never sees or handles a
fingerprint or face scan itself -- the OS does that, and only tells the
browser "yes, verified" or "no."

IMPORTANT -- read before deploying:
- WebAuthn credentials are bound to a "Relying Party ID," which is
  basically your domain. A passkey registered while testing on
  localhost will NOT work once deployed to a real domain -- it has to
  be registered again there. Set WEBAUTHN_RP_ID to your real domain
  (no scheme, no port -- e.g. "myapp.streamlit.app") once deployed.
- WebAuthn requires a secure context: HTTPS in production (localhost is
  exempted by browsers for local development).
- This code has been tested against a synthetic, spec-compliant
  authenticator (see the test script used during development), which
  verifies the cryptographic logic is correct. It has NOT been tested
  against a real browser prompting real biometric hardware -- that step
  needs real devices, which this environment doesn't have.

Security model: verifying a passkey proves "this is the device and
biometric that was registered for this account." It does not, by itself,
hand us anything usable to decrypt that account's notes (WebAuthn is a
signature challenge-response, not a key-agreement protocol in the simple
form used here). So biometric login re-uses the SAME server-side escrow
key that email/OTP password reset already uses (see crypto_utils.py and
db.py) to unwrap the account's master key after a passkey is verified.
This doesn't introduce a new weakening of the security model -- it's the
same trade-off already made and documented for OTP reset, just with a
second way to invoke it.
"""

import os
import base64

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url


def rp_id() -> str:
    return os.environ.get("WEBAUTHN_RP_ID", "localhost")


def rp_name() -> str:
    return os.environ.get("WEBAUTHN_RP_NAME", "CipherNotes")


def origin() -> str:
    """The exact origin the browser will report. Must match what the
    browser actually shows in the address bar (scheme + host + port).
    Defaults to plain local development; override for a real deployment,
    e.g. WEBAUTHN_ORIGIN=https://your-app.streamlit.app"""
    return os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:8501")


def build_registration_options(user_id: int, username: str, existing_credential_ids: list):
    """Generates the options the browser needs to create a new passkey.
    existing_credential_ids (list of base64url strings) are excluded so
    the same device/account combo can't register twice by accident."""
    options = generate_registration_options(
        rp_id=rp_id(),
        rp_name=rp_name(),
        user_id=str(user_id).encode("utf-8"),
        user_name=username,
        user_display_name=username,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
            for cid in existing_credential_ids
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    # options_to_json() gives the browser-ready JSON; we also need the
    # raw challenge bytes (base64url) to check against on verification.
    return options


def verify_registration(response_json: str, expected_challenge_b64url: str):
    """Verifies what the browser sent back after navigator.credentials.create().
    response_json is the raw JSON string the browser produced. Returns
    (credential_id_b64url, public_key_bytes, sign_count) on success;
    raises an exception on failure (caller should catch it)."""
    from webauthn.helpers import parse_registration_credential_json

    credential = parse_registration_credential_json(response_json)
    result = verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge_b64url),
        expected_origin=origin(),
        expected_rp_id=rp_id(),
        require_user_verification=True,
    )
    return (
        bytes_to_base64url(result.credential_id),
        result.credential_public_key,
        result.sign_count,
    )


def build_authentication_options(allowed_credential_ids: list):
    """Generates the options the browser needs for navigator.credentials.get().
    allowed_credential_ids: base64url strings of this user's registered
    passkeys."""
    options = generate_authentication_options(
        rp_id=rp_id(),
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
            for cid in allowed_credential_ids
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options


def verify_authentication(
    response_json: str,
    expected_challenge_b64url: str,
    stored_public_key: bytes,
    stored_sign_count: int,
):
    """Verifies what the browser sent back after navigator.credentials.get().
    response_json is the raw JSON string the browser produced. Returns
    the new sign_count on success; raises an exception on failure."""
    from webauthn.helpers import parse_authentication_credential_json

    credential = parse_authentication_credential_json(response_json)
    result = verify_authentication_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge_b64url),
        expected_origin=origin(),
        expected_rp_id=rp_id(),
        credential_public_key=stored_public_key,
        credential_current_sign_count=stored_sign_count,
        require_user_verification=True,
    )
    return result.new_sign_count