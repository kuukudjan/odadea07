"""
supabase_client.py — ODADEAƐ07 Supabase helper

Thin wrapper around the Supabase REST client. Falls back to
local CSV files if Supabase env vars are not set, so you can
develop locally without Supabase.

Environment variables (set these on Render):
  SUPABASE_URL — your project URL (https://xxxx.supabase.co)
  SUPABASE_KEY — your anon or service_role key

─────────────────────────────────────────────────────────────
CHANGELOG
─────────────────────────────────────────────────────────────
2026-09-26 — Fix: fetch_all() no longer uses .range() without
             .order(), which caused PostgREST to return 400 and
             made every read silently return an empty list.
             Also logs failures to stdout so they appear in
             Render's Logs tab.
─────────────────────────────────────────────────────────────
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

    Two-stage approach:
      1. Simple select with .limit(1000) — no .range(), no .order().
         This avoids the PostgREST bug where .range() without .order()
         returns 400 Bad Request on newer Supabase versions.
      2. If exactly 1000 rows came back, paginate with an explicit
         .order() column so .range() works reliably.
    """
    client = get_client()
    if client is None:
        return []
    try:
        # ── Stage 1: simple select. No .range() → no bug. ──
        resp = client.table(table_name).select('*').limit(1000).execute()
        first_page = resp.data or []

        if len(first_page) < 1000:
            # We have everything in one page.
            return first_page

        # ── Stage 2: more than 1000 rows. Paginate with an order column. ──
        all_rows = list(first_page)

        # Pick an order column that exists. Most tables have one of these.
        sample = first_page[0] if first_page else {}
        order_col = None
        for candidate in ('created_at', 'registered_at', 'voted_at'):
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
        # Print to stdout so it shows up in Render logs
        print(f'[Supabase fetch failed for {table_name}]: {e}')
        logger.error(f'Supabase fetch failed for {table_name}: {e}')
        return []


def fetch_one(table_name, id_col, id_val):
    """
    Fetch a single row by matching id_col == id_val.
    Returns dict or None.
    """
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
        logger.error(f'Supabase fetch_one failed for {table_name}: {e}')
        return None


# ═══════════════════════════════════════════════════════════
# WRITE
# ═══════════════════════════════════════════════════════════
def insert_row(table_name, row):
    """
    Insert a single row. Returns True on success, False on failure.
    Failures print to stdout so they appear in Render logs.
    """
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
    """Delete rows where col == val. Returns True if the call succeeded."""
    client = get_client()
    if client is None:
        return False
    try:
        client.table(table_name).delete().eq(col, val).execute()
        return True
    except Exception as e:
        print(f'[Supabase delete failed for {table_name}]: {e}')
        logger.error(f'Supabase delete failed for {table_name}: {e}')
        return False


def update_where(table_name, id_col, id_val, updates):
    """Update rows where id_col == id_val with the given dict."""
    client = get_client()
    if client is None:
        return False
    try:
        client.table(table_name).update(updates).eq(id_col, id_val).execute()
        return True
    except Exception as e:
        print(f'[Supabase update failed for {table_name}]: {e}')
        logger.error(f'Supabase update failed for {table_name}: {e}')
        return False


# ═══════════════════════════════════════════════════════════
# CSV HELPERS (used by reports)
# ═══════════════════════════════════════════════════════════
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


# ═══════════════════════════════════════════════════════════
# FILTER HELPER
# ═══════════════════════════════════════════════════════════
def filter_rows(rows, **filters):
    """
    Filter rows client-side. Each filter is (field, value).
    Value comparison is case-insensitive string match.
    """
    out = rows
    for field, value in filters.items():
        if value in (None, '', 'all', 'ALL'):
            continue
        v = str(value).lower()
        out = [r for r in out if v in str(r.get(field, '')).lower()]
    return out