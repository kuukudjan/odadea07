"""
supabase_client.py — ODADEAƐ07 Supabase helper (extended)

Wrappers around the Supabase REST client. Falls back to CSV
files if SUPABASE_URL / SUPABASE_KEY are not set.

Environment variables (set these on Render):
  SUPABASE_URL — your project URL (https://xxxx.supabase.co)
  SUPABASE_KEY — your anon or service_role key
"""

import os
import io
import csv
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

SUPABASE_URL = os.environ.get('SUPABASE_URL', '').strip()
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '').strip()
SUPABASE_ENABLED = bool(SUPABASE_URL and SUPABASE_KEY)

_client = None


# ═══════════════════════════════════════════════════════════
# CLIENT
# ═══════════════════════════════════════════════════════════
def get_client():
    """Return a cached Supabase client, or None if not configured."""
    global _client
    if not SUPABASE_ENABLED:
        return None
    if _client is None:
        try:
            from supabase import create_client
            _client = create_client(SUPABASE_URL, SUPABASE_KEY)
        except Exception as e:
            print(f'[Supabase client init failed]: {e}')
            logger.error(f'Supabase client init failed: {e}')
            return None
    return _client


# ═══════════════════════════════════════════════════════════
# READ
# ═══════════════════════════════════════════════════════════
def fetch_all(table_name):
    """
    Return list of dicts (all rows) from a Supabase table.
    Two-stage: simple select first; paginate only if needed.
    """
    client = get_client()
    if client is None:
        return []
    try:
        resp = client.table(table_name).select('*').limit(1000).execute()
        first_page = resp.data or []

        if len(first_page) < 1000:
            return first_page

        all_rows = list(first_page)
        sample = first_page[0] if first_page else {}
        order_col = None
        for candidate in ('created_at', 'registered_at', 'voted_at', 'happened_at'):
            if candidate in sample:
                order_col = candidate
                break

        page_size = 1000
        offset = 1000
        while True:
            q = client.table(table_name).select('*')
            if order_col:
                q = q.order(order_col)
            resp = q.range(offset, offset + page_size - 1).execute()
            rows = resp.data or []
            all_rows.extend(rows)
            if len(rows) < page_size:
                break
            offset += page_size
        return all_rows
    except Exception as e:
        print(f'[Supabase fetch failed for {table_name}]: {e}')
        logger.error(f'Supabase fetch failed for {table_name}: {e}')
        return []


def fetch_one(table_name, id_col, id_val):
    client = get_client()
    if client is None:
        return None
    try:
        resp = (client.table(table_name)
                .select('*')
                .eq(id_col, id_val)
                .limit(1)
                .execute())
        rows = resp.data or []
        return rows[0] if rows else None
    except Exception as e:
        print(f'[Supabase fetch_one failed for {table_name}]: {e}')
        return None


# ═══════════════════════════════════════════════════════════
# WRITE
# ═══════════════════════════════════════════════════════════
def insert_row(table_name, row):
    client = get_client()
    if client is None:
        return False
    try:
        client.table(table_name).insert(row).execute()
        return True
    except Exception as e:
        print(f'[Supabase insert failed for {table_name}]: {e}')
        logger.error(f'Supabase insert failed for {table_name}: {e}')
        return False


def delete_where(table_name, col, val):
    client = get_client()
    if client is None:
        return False
    try:
        client.table(table_name).delete().eq(col, val).execute()
        return True
    except Exception as e:
        print(f'[Supabase delete failed for {table_name}]: {e}')
        return False


def update_where(table_name, id_col, id_val, updates):
    client = get_client()
    if client is None:
        return False
    try:
        client.table(table_name).update(updates).eq(id_col, id_val).execute()
        return True
    except Exception as e:
        print(f'[Supabase update failed for {table_name}]: {e}')
        return False


def upsert_row(table_name, row, on_conflict):
    """Insert or update based on a unique column."""
    client = get_client()
    if client is None:
        return False
    try:
        client.table(table_name).upsert(row, on_conflict=on_conflict).execute()
        return True
    except Exception as e:
        print(f'[Supabase upsert failed for {table_name}]: {e}')
        return False


# ═══════════════════════════════════════════════════════════
# CSV HELPERS
# ═══════════════════════════════════════════════════════════
def rows_to_csv_bytes(rows):
    if not rows:
        return b''
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return buf.getvalue().encode('utf-8')


def fetch_table_csv(table_name):
    return rows_to_csv_bytes(fetch_all(table_name))


# ═══════════════════════════════════════════════════════════
# RATE LIMIT (persistent — replaces the in-memory version)
# ═══════════════════════════════════════════════════════════
def rate_limit_get(key):
    """Return the stored attempts list for a key, or []."""
    row = fetch_one('rate_limit', 'key', key)
    if not row:
        return []
    try:
        return json.loads(row.get('attempts', '[]'))
    except Exception:
        return []


def rate_limit_set(key, attempts):
    """Store attempts list for a key."""
    row = {
        'key': key,
        'attempts': json.dumps(attempts),
        'updated_at': datetime.now().isoformat(),
    }
    return upsert_row('rate_limit', row, 'key')


# ═══════════════════════════════════════════════════════════
# LOGIN HISTORY
# ═══════════════════════════════════════════════════════════
def log_login(subject_type, subject_id, ip, user_agent, success):
    """Append a login attempt to login_history."""
    import time, random
    entry = {
        'entry_id': f"LOG{int(time.time())}{random.randint(100,999)}",
        'subject_type': subject_type,
        'subject_id': subject_id or '',
        'ip_address': ip or '',
        'user_agent': (user_agent or '')[:300],
        'success': 'True' if success else 'False',
        'happened_at': datetime.now().isoformat(),
    }
    return insert_row('login_history', entry)


# ═══════════════════════════════════════════════════════════
# FILTER HELPER
# ═══════════════════════════════════════════════════════════
def filter_rows(rows, **filters):
    out = rows
    for field, value in filters.items():
        if value in (None, '', 'all', 'ALL'):
            continue
        v = str(value).lower()
        out = [r for r in out if v in str(r.get(field, '')).lower()]
    return out