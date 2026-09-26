"""
two_factor.py — TOTP 2FA helpers using pyotp.
"""

import pyotp


def new_secret():
    """Generate a new base32 TOTP secret."""
    return pyotp.random_base32()


def verify(secret, code):
    """Verify a 6-digit TOTP code against a secret."""
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(str(code).strip(), valid_window=1)
    except Exception:
        return False


def provisioning_url(secret, email, issuer='ODADEAƐ07'):
    """Return the otpauth:// URL for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)