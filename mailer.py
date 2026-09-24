"""
mailer.py — ODADEAƐ07 email sender

Uses SMTP. Works with Gmail, Resend, Brevo, or any SMTP server.

Environment variables (set on Render):
  SMTP_HOST       e.g. smtp.gmail.com
  SMTP_PORT       e.g. 587
  SMTP_USER       your email address
  SMTP_PASSWORD   app password (not your real password)
  SMTP_FROM       "ODADEAƐ07 <noreply@yourapp.com>"
  SMTP_USE_TLS    "true" (default) or "false"
"""

import os
import smtplib
import ssl
from email.message import EmailMessage

SMTP_HOST     = os.environ.get('SMTP_HOST', '').strip()
SMTP_PORT     = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER     = os.environ.get('SMTP_USER', '').strip()
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '').strip()
SMTP_FROM     = os.environ.get('SMTP_FROM', SMTP_USER or 'noreply@odadea07.local').strip()
SMTP_USE_TLS  = os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true'

EMAIL_ENABLED = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)


def send_email(to_address, subject, body_text, body_html=None):
    """
    Send an email. Returns (success: bool, error_message: str|None).
    If SMTP is not configured, prints to console and returns success=False.
    """
    if not EMAIL_ENABLED:
        print(f'[mailer] SMTP not configured. Would send to {to_address}:')
        print(f'[mailer] Subject: {subject}')
        print(f'[mailer] Body:\n{body_text}')
        return False, 'Email is not configured on this server.'

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = to_address
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype='html')

    try:
        context = ssl.create_default_context()
        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                server.starttls(context=context)
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20, context=context) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        return True, None
    except Exception as e:
        print(f'[mailer] Failed to send to {to_address}: {e}')
        return False, str(e)


def send_password_reset(to_address, full_name, reset_url):
    """Send the password reset email."""
    subject = 'Reset your ODADEAƐ07 password'
    text = f"""Hi {full_name},

Someone (hopefully you) asked to reset the password for your ODADEAƐ07 account.

Click this link to choose a new password:

{reset_url}

The link expires in 1 hour. If you didn't ask for this, you can safely ignore this email — your password won't change.

— ODADEAƐ07
"""
    html = f"""<!DOCTYPE html>
<html><body style="font-family:Arial,sans-serif;background:#f6f8ff;padding:24px;">
  <div style="max-width:520px;margin:auto;background:#fff;border-radius:12px;
              padding:28px;border-top:5px solid #1a3fbf;">
    <h2 style="color:#1a3fbf;margin:0 0 12px;">Reset your ODADEAƐ07 password</h2>
    <p style="color:#333;">Hi <strong>{full_name}</strong>,</p>
    <p style="color:#333;">Click the button below to choose a new password.
       The link expires in 1 hour.</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="{reset_url}"
         style="background:#1a3fbf;color:#fff;padding:12px 24px;border-radius:999px;
                text-decoration:none;font-weight:bold;display:inline-block;">
        Choose a new password
      </a>
    </p>
    <p style="color:#666;font-size:13px;">Or paste this link into your browser:</p>
    <p style="color:#666;font-size:13px;word-break:break-all;">{reset_url}</p>
    <hr style="border:none;border-top:1px solid #e3e7ee;margin:24px 0;">
    <p style="color:#999;font-size:12px;">
      If you didn't ask for this, ignore this email — your password won't change.
    </p>
    <p style="color:#999;font-size:12px;text-align:center;margin-top:16px;">
      ODADEAƐ07 — PRESEC 2007 Year Group
    </p>
  </div>
</body></html>
"""
    return send_email(to_address, subject, text, html)