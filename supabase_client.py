"""
supabase_client.py — ODADEAƐ07 Supabase helper

Thin wrapper around the Supabase REST client. Falls back to
local CSV files if Supabase env vars are not set, so you can
develop locally without Supabase.

Environment variables (set these on Render):
  SUPABASE_URL — your project URL (https://xxxx.supabase.co)
  SUPABASE_KEY — your anon or service_role key
"""

import os
import io
import csv
import logging

logger = logging.getLogger(__name__)

SUPABASE_URL = os.environ.get('SUPABASE_URL', '').strip()
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '').strip()
SUPABASE_ENABLED = bool(SUPABASE_URL and SUPABASE_KEY)

_client = None


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
            logger.error(f'Supabase client init failed: {e}')
            return None
    return _client


def fetch_all(table_name):
    """Return list of dicts (all rows) from a Supabase table."""
    client = get_client()
    if client is None:
        return []
    try:
        # Supabase default limit is 1000; paginate to get everything
        all_rows = []
        page_size = 1000
        offset = 0
        while True:
            resp = (client.table(table_name)
                    .select('*')
                    .range(offset, offset + page_size - 1)
                    .execute())
            rows = resp.data or []
            all_rows.extend(rows)
            if len(rows) < page_size:
                break
            offset += page_size
        return all_rows
    except Exception as e:
        logger.error(f'Supabase fetch failed for {table_name}: {e}')
        return []


def rows_to_csv_bytes(rows):
    """Convert a list of dicts to UTF-8 CSV bytes."""
    if not rows:
        return b''
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return buf.getvalue().encode('utf-8')


def fetch_table_csv(table_name):
    """Fetch a whole table and return CSV bytes."""
    return rows_to_csv_bytes(fetch_all(table_name))


def filter_rows(rows, **filters):
    """
    Filter rows client-side. Each filter is (field, value).
    Value comparison is case-insensitive string match for
    substring OR exact match.
    """
    out = rows
    for field, value in filters.items():
        if value in (None, '', 'all', 'ALL'):
            continue
        v = str(value).lower()
        out = [r for r in out if v in str(r.get(field, '')).lower()]
    return out