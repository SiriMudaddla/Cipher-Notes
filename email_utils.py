"""
email_utils.py
--------------
Sends the one-time password (OTP) reset code by email, using plain SMTP.

Configure it with environment variables:
    SMTP_HOST       e.g. smtp.gmail.com
    SMTP_PORT       defaults to 587 (STARTTLS)
    SMTP_USERNAME   the account that logs into the SMTP server
    SMTP_PASSWORD   an app password (not your regular account password,
                    if using Gmail -- see README)
    SMTP_FROM       the "From" address shown to recipients (defaults to
                    SMTP_USERNAME if not set)

If these aren't set, is_configured() returns False. app.py uses this to
fall back to a "dev mode" that shows the OTP directly in the browser
instead of emailing it, so the app is still testable locally without
setting up a real mail account.
"""

import os
import smtplib
from email.mime.text import MIMEText

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USERNAME)


def is_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD)


def send_otp_email(to_email: str, otp: str):
    """Sends the OTP code to the given address. Raises an exception if
    sending fails (bad credentials, unreachable server, etc.) -- callers
    should catch this and show a friendly error."""
    if not is_configured():
        raise RuntimeError(
            "Email sending isn't configured (set SMTP_HOST, SMTP_USERNAME, "
            "SMTP_PASSWORD)."
        )

    body = (
        f"Your Secure Notes password reset code is: {otp}\n\n"
        "This code expires in 10 minutes. If you didn't request a "
        "password reset, you can safely ignore this email."
    )
    msg = MIMEText(body)
    msg["Subject"] = "Secure Notes - Password Reset Code"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, [to_email], msg.as_string())