"""
password_reset.py — ODADEAƐ07 password reset logic

Stores one-time reset tokens in Supabase (or CSV fallback).
Tokens expire after 1 hour.

Data integrity: only the `password_hash` field is ever updated.
Member data (name, email, votes, dues, contributions) is NEVER touched.
"""

import os
import csv
import time
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta

import supabase_client as sb
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
TOKENS_FILE = os.path.join(DATA_DIR, 'password_resets.csv')

TOKEN_TTL_MINUTES = 60
T_MEMBERS = 'members'
T_TOKENS  = 'password_resets'


# ─────────────────────────────────────────────────────────
# TOKEN STORAGE (Supabase or CSV fallback)
# ─────────────────────────────────────────────────────────
def _load_tokens_csv():
    if not os.path.exists(TOKENS_FILE):
        return []
    with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def _save_tokens_csv(rows):
    os.makedirs(DATA_DIR, exist_ok=True)
    if not rows:
        with open(TOKENS_FILE, 'w', encoding='utf-8') as f:
            f.write('token,member_id,email,expires_at,used\n')
        return
    with open(TOKENS_FILE, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def _insert_token(row):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(T_TOKENS).insert(row).execute()
                return True
            except Exception as e:
                print(f'[password_reset] Supabase insert failed: {e}')
    rows = _load_tokens_csv()
    rows.append(row)
    _save_tokens_csv(rows)
    return True


def _find_token(token):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                resp = (client.table(T_TOKENS)
                        .select('*')
                        .eq('token', token)
                        .limit(1)
                        .execute())
                if resp.data:
                    return resp.data[0]
            except Exception as e:
                print(f'[password_reset] Supabase query failed: {e}')
    for r in _load_tokens_csv():
        if r.get('token') == token:
            return r
    return None


def _mark_token_used(token):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(T_TOKENS).update({'used': 'True'}).eq('token', token).execute()
                return True
            except Exception as e:
                print(f'[password_reset] Supabase update failed: {e}')
    rows = _load_tokens_csv()
    for r in rows:
        if r.get('token') == token:
            r['used'] = 'True'
    _save_tokens_csv(rows)
    return True


def _cleanup_expired():
    """Remove expired or used tokens (housekeeping)."""
    now_iso = datetime.now().isoformat()
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(T_TOKENS).delete().lt('expires_at', now_iso).execute()
                client.table(T_TOKENS).delete().eq('used', 'True').execute()
            except Exception as e:
                print(f'[password_reset] Cleanup failed: {e}')
            return
    rows = _load_tokens_csv()
    rows = [r for r in rows
            if r.get('expires_at', '') > now_iso and r.get('used', 'False') != 'True']
    _save_tokens_csv(rows)


# ─────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────
def create_reset_token(member_id, email):
    """
    Generate a new one-time reset token and store it.
    Returns the token string.
    """
    _cleanup_expired()

    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(minutes=TOKEN_TTL_MINUTES)).isoformat()

    _insert_token({
        'token': token,
        'member_id': member_id,
        'email': email,
        'expires_at': expires_at,
        'used': 'False',
    })
    return token


def verify_token(token):
    """
    Check if token is valid (exists, not used, not expired).
    Returns the token row dict if valid, else None.
    """
    if not token:
        return None
    row = _find_token(token)
    if not row:
        return None
    if str(row.get('used', 'False')).lower() == 'true':
        return None
    try:
        expires = datetime.fromisoformat(row['expires_at'])
    except (ValueError, KeyError):
        return None
    if datetime.now() > expires:
        return None
    return row


def consume_token(token, new_password):
    """
    Verify token, update the member's password_hash, mark token used.
    Returns (success: bool, message: str).
    Only the password_hash field is ever modified.
    """
    row = verify_token(token)
    if not row:
        return False, 'This reset link is invalid or has expired.'

    member_id = row.get('member_id')
    if not member_id:
        return False, 'Reset link is malformed.'

    new_hash = generate_password_hash(new_password)

    # Update ONLY password_hash, nothing else
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is None:
            return False, 'Database temporarily unavailable.'
        try:
            client.table(T_MEMBERS).update(
                {'password_hash': new_hash}
            ).eq('member_id', member_id).execute()
        except Exception as e:
            print(f'[password_reset] Password update failed: {e}')
            return False, 'Could not update password. Please try again.'
    else:
        # CSV fallback
        members_path = os.path.join(DATA_DIR, 'members.csv')
        if not os.path.exists(members_path):
            return False, 'Member database not found.'
        import pandas as pd
        df = pd.read_csv(members_path, dtype=str).fillna('')
        mask = df['member_id'] == member_id
        if not mask.any():
            return False, 'Member not found.'
        df.loc[mask, 'password_hash'] = new_hash
        df.to_csv(members_path, index=False)

    _mark_token_used(token)
    return True, 'Your password has been updated. Please log in.'