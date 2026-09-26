"""
admin_routes.py — ODADEAƐ07 Admin Panel (extended)

New features:
  • Poll scheduling (open_at, close_at, anonymous)
  • Member roles (member / treasurer / secretary / admin)
  • Member suspension
  • Bulk actions (select many, delete)
  • CSV import for members
  • Search in members list
  • Date filters in reports
  • PDF report downloads
  • Per-admin accounts
  • Login history view
"""

import os
import io
import csv
import json
import time
import random
import zipfile
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from io import BytesIO

import pandas as pd
from flask import (Blueprint, render_template_string, request, session,
                   redirect, url_for, flash, send_file, make_response)
from flask_wtf.csrf import generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash

import supabase_client as sb
import two_factor as tf
from chart_helpers import bar_chart, line_chart, CHART_JS_CDN
from pdf_helpers import build_pdf

BASE_DIR            = os.path.dirname(os.path.abspath(__file__))
DATA_DIR            = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
MEMBERS_FILE        = os.path.join(DATA_DIR, 'members.csv')
POLLS_FILE          = os.path.join(DATA_DIR, 'polls.csv')
VOTES_FILE          = os.path.join(DATA_DIR, 'votes.csv')
CONTRIBUTIONS_FILE  = os.path.join(DATA_DIR, 'contributions.csv')
CAMPAIGNS_FILE      = os.path.join(DATA_DIR, 'contributions_campaigns.csv')
DUES_FILE           = os.path.join(DATA_DIR, 'dues.csv')
DUES_CAMPAIGNS_FILE = os.path.join(DATA_DIR, 'dues_campaigns.csv')

os.makedirs(DATA_DIR, exist_ok=True)

# Legacy shared password — still supported for backward compatibility
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'CHANGE-ME-NOW')

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

T_MEMBERS        = 'members'
T_POLLS          = 'polls'
T_VOTES          = 'votes'
T_CONTRIBUTIONS  = 'contributions'
T_CAMPAIGNS      = 'contributions_campaigns'
T_DUES           = 'dues'
T_DUES_CAMPAIGNS = 'dues_campaigns'
T_ADMIN_USERS    = 'admin_users'
T_LOGIN_HISTORY  = 'login_history'

MONTHS = ['January','February','March','April','May','June',
          'July','August','September','October','November','December']
TITLES = ['Mr','Mrs','Miss','Dr','Rev','Prof','Hon','Nana','Nii']
ROLES  = ['admin','treasurer','secretary','member']


# ─────────────────────────────────────────────────────────
# RATE LIMITER (persistent)
# ─────────────────────────────────────────────────────────
_WINDOW = timedelta(minutes=15)
_MAX    = 5


def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _parse_iso(s):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _rate_locked(prefix, ip):
    key = f'{prefix}:{ip}'
    attempts = sb.rate_limit_get(key)
    now = datetime.now()
    attempts = [t for t in attempts if _parse_iso(t) and _parse_iso(t) > now - _WINDOW]
    return len(attempts) >= _MAX, attempts, key


def _rate_record(key, attempts):
    sb.rate_limit_set(key, attempts + [datetime.now().isoformat()])


def _rate_clear(prefix, ip):
    sb.rate_limit_set(f'{prefix}:{ip}', [])


# ─────────────────────────────────────────────────────────
# DATA HELPERS
# ─────────────────────────────────────────────────────────
def _load_csv(path):
    if os.path.exists(path):
        return pd.read_csv(path, dtype=str).fillna('')
    return pd.DataFrame()


def _save_csv(path, df):
    df.to_csv(path, index=False)


def _load(table, csv_path):
    if sb.SUPABASE_ENABLED:
        rows = sb.fetch_all(table)
        if rows:
            return pd.DataFrame(rows).fillna('').astype(str)
        return pd.DataFrame()
    return _load_csv(csv_path)


def _insert(table, csv_path, row):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(table).insert(row).execute()
                return True
            except Exception as e:
                print(f'[Supabase insert failed for {table}]: {e}')
    df = _load_csv(csv_path)
    new = pd.DataFrame([row])
    out = pd.concat([df, new], ignore_index=True) if not df.empty else new
    _save_csv(csv_path, out)
    return True


def _delete_where(table, csv_path, col, val):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(table).delete().eq(col, val).execute()
                return True
            except Exception as e:
                print(f'[Supabase delete failed]: {e}')
                return False
    df = _load_csv(csv_path)
    if df.empty or col not in df.columns:
        return False
    df = df[df[col].astype(str) != str(val)]
    _save_csv(csv_path, df)
    return True


def _update_where(table, csv_path, id_col, id_val, updates):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(table).update(updates).eq(id_col, id_val).execute()
                return True
            except Exception as e:
                print(f'[Supabase update failed]: {e}')
                return False
    df = _load_csv(csv_path)
    if df.empty or id_col not in df.columns:
        return False
    mask = df[id_col].astype(str) == str(id_val)
    if not mask.any():
        return False
    for k, v in updates.items():
        df.loc[mask, k] = v
    _save_csv(csv_path, df)
    return True


def _sanitize(s, max_len=200):
    if s is None:
        return ''
    s = str(s).strip().replace('\r', '').replace('\n', '').replace('\x00', '')
    return s[:max_len]


def _build_full_name(first, middle, last):
    parts = [str(first or '').strip(),
             str(middle or '').strip(),
             str(last or '').strip()]
    return ' '.join(p for p in parts if p)


def _csv_response(rows, filename):
    buf = io.StringIO()
    if rows:
        keys = []
        for r in rows:
            for k in r.keys():
                if k not in keys:
                    keys.append(k)
        w = csv.DictWriter(buf, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, '') for k in keys})
    resp = make_response(buf.getvalue().encode('utf-8'))
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return resp


def _is_admin():
    return bool(session.get('is_admin') or session.get('admin_id'))


def _admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not _is_admin():
            flash('Admin login required.', 'warning')
            return redirect(url_for('admin.login'))
        return f(*a, **kw)
    return wrapper


# ─────────────────────────────────────────────────────────
# LAYOUT
# ─────────────────────────────────────────────────────────
ADMIN_LAYOUT = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Admin — ODADEAƐ07</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    {{ chartjs|safe }}
</head>
<body>
<header class="main-header">
    <div class="header-content">
        <a href="{{ url_for('admin.home') }}" class="logo-section">
            <img src="{{ url_for('static', filename='images/presec-badge.png') }}"
                 class="school-badge" onerror="this.style.display='none'">
            <div class="logo-text">
                <h1>ODADEAƐ07 <span style="color:#f5c518;font-size:0.7em;">ADMIN</span></h1>
                <p>PRESEC 2007 Year Group</p>
            </div>
        </a>
        <nav class="main-nav">
            {% if session.is_admin or session.admin_id %}
                <a href="{{ url_for('admin.home') }}">📊 Dashboard</a>
                <a href="{{ url_for('admin.polls') }}">🗳️ Polls</a>
                <a href="{{ url_for('admin.contrib') }}">🎯 Contributions</a>
                <a href="{{ url_for('admin.dues') }}">📅 Dues</a>
                <a href="{{ url_for('admin.members') }}">👥 Members</a>
                <a href="{{ url_for('admin.admin_users') }}">🔐 Admins</a>
                <a href="{{ url_for('admin.reports') }}">📈 Reports</a>
                <a href="{{ url_for('admin.logout') }}" class="btn-register">Logout</a>
            {% endif %}
        </nav>
    </div>
</header>

{% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        <div class="flash-messages">
            {% for cat, msg in messages %}
                <div class="flash flash-{{ cat }}">{{ msg }}</div>
            {% endfor %}
        </div>
    {% endif %}
{% endwith %}

<main class="main-content">{{ body|safe }}</main>

<footer class="main-footer">
    <div class="footer-content">
        <p><strong>ODADEAƐ07 Admin Panel</strong></p>
        <p class="motto">"In Lumine Tuo Videbimus Lumen"</p>
    </div>
</footer>
</body>
</html>
"""


def _page(body):
    return render_template_string(
        ADMIN_LAYOUT,
        body=body,
        csrf_token=generate_csrf,
        chartjs=CHART_JS_CDN,
    )


# ─────────────────────────────────────────────────────────
# LOGIN / LOGOUT (individual + legacy password)
# ─────────────────────────────────────────────────────────
@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    ip = _client_ip()
    if request.method == 'POST':
        locked, attempts, key = _rate_locked('admin-login', ip)
        if locked:
            flash('Too many attempts. Locked for 15 minutes.', 'danger')
            return redirect(url_for('admin.login'))

        email = _sanitize(request.form.get('email', ''), 120).lower()
        pwd   = request.form.get('password', '')

        # Try individual admin account first
        admins = _load(T_ADMIN_USERS, os.path.join(DATA_DIR, 'admin_users.csv'))
        if email and not admins.empty:
            row = admins[admins['email'].str.lower() == email]
            if not row.empty:
                stored = row.iloc[0].get('password_hash', '')
                try:
                    if check_password_hash(stored, pwd):
                        # Check 2FA
                        if str(row.iloc[0].get('totp_enabled', 'False')).lower() == 'true':
                            session['pending_admin_id'] = row.iloc[0]['admin_id']
                            return redirect(url_for('admin.login_2fa'))
                        _rate_clear('admin-login', ip)
                        session['admin_id'] = row.iloc[0]['admin_id']
                        session['admin_email'] = email
                        session['is_admin'] = True
                        session.permanent = True
                        _update_where(T_ADMIN_USERS,
                                      os.path.join(DATA_DIR, 'admin_users.csv'),
                                      'admin_id', row.iloc[0]['admin_id'],
                                      {'last_login': datetime.now().isoformat()})
                        sb.log_login('admin', row.iloc[0]['admin_id'], ip,
                                     request.headers.get('User-Agent', ''), True)
                        flash(f'Welcome, {row.iloc[0].get("full_name", "admin")}.', 'success')
                        return redirect(url_for('admin.home'))
                except Exception:
                    pass

        # Fall back to legacy shared password
        if pwd == ADMIN_PASSWORD:
            _rate_clear('admin-login', ip)
            session['is_admin'] = True
            session.permanent = True
            sb.log_login('admin', None, ip,
                         request.headers.get('User-Agent', ''), True)
            flash('Welcome, admin.', 'success')
            return redirect(url_for('admin.home'))

        _rate_record(key, attempts)
        sb.log_login('admin', None, ip,
                     request.headers.get('User-Agent', ''), False)
        remaining = _MAX - (len(attempts) + 1)
        flash(f'Invalid credentials. {max(remaining, 0)} attempts left.', 'danger')

    body = render_template_string("""
    <div class="form-container">
      <h1>🛡️ Admin Login</h1>
      <p class="form-subtitle">Sign in with your admin email, or use the shared password</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group"><label>Email (if you have a personal admin account)</label>
          <input type="email" name="email" autofocus></div>
        <div class="form-group"><label>Password</label>
          <input type="password" name="password" required></div>
        <button class="btn btn-primary btn-full">🔓 Enter</button>
      </form>
      <p class="form-footer">
        <a href="{{ url_for('index') }}">← Back to site</a>
      </p>
    </div>
    """)
    return _page(body)


@admin_bp.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    aid = session.get('pending_admin_id')
    if not aid:
        return redirect(url_for('admin.login'))
    if request.method == 'POST':
        code = _sanitize(request.form.get('code', ''), 6)
        row = sb.fetch_one(T_ADMIN_USERS, 'admin_id', aid)
        if row and tf.verify(row.get('totp_secret', ''), code):
            session.pop('pending_admin_id', None)
            session['admin_id'] = aid
            session['is_admin'] = True
            session.permanent = True
            flash('Welcome.', 'success')
            return redirect(url_for('admin.home'))
        flash('Invalid code.', 'danger')
    body = render_template_string("""
    <div class="form-container">
      <h1>Two-factor</h1>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group"><label>6-digit code</label>
          <input name="code" required maxlength="6" inputmode="numeric" autofocus></div>
        <button class="btn btn-primary btn-full">Verify</button>
      </form>
    </div>
    """)
    return _page(body)


@admin_bp.route('/logout')
def logout():
    session.pop('is_admin', None)
    session.pop('admin_id', None)
    session.pop('admin_email', None)
    flash('Logged out.', 'info')
    return redirect(url_for('admin.login'))


# ─────────────────────────────────────────────────────────
# DASHBOARD (with charts)
# ─────────────────────────────────────────────────────────
@admin_bp.route('/')
@_admin_required
def home():
    members = _load(T_MEMBERS, MEMBERS_FILE)
    polls   = _load(T_POLLS, POLLS_FILE)
    votes   = _load(T_VOTES, VOTES_FILE)
    contrib = _load(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE)
    camps   = _load(T_CAMPAIGNS, CAMPAIGNS_FILE)
    dues    = _load(T_DUES, DUES_FILE)
    duesc   = _load(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE)

    def _sum(df):
        if df.empty or 'amount' not in df.columns:
            return 0.0
        return float(pd.to_numeric(df['amount'], errors='coerce').fillna(0).sum())

    stats = {
        'members': len(members),
        'polls': len(polls),
        'votes': len(votes),
        'contrib_total': _sum(contrib),
        'camps': len(camps),
        'dues_total': _sum(dues),
        'dues_plans': len(duesc),
    }

    # Charts
    dues_chart = ''
    if not dues.empty:
        df = dues.copy()
        df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
        df['month'] = df['created_at'].str[:7]
        g = df.groupby('month')['amount'].sum().sort_index()
        dues_chart = line_chart('dues-monthly',
                                list(g.index), [float(v) for v in g.values])

    member_status_chart = ''
    if not members.empty and 'status' in members.columns:
        counts = members['status'].replace('', 'active').value_counts()
        member_status_chart = bar_chart('member-status',
                                        list(counts.index),
                                        [int(v) for v in counts.values])

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🛡️ Admin Dashboard</h1><p class="subtitle">Live data</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.reports') }}" class="btn btn-primary">📈 All Reports</a>
        <a href="{{ url_for('admin.logout') }}" class="btn btn-secondary">Logout</a>
      </div>
    </div>

    <div class="report-stats-grid">
      <div class="report-stat-card"><div class="stat-icon">👥</div>
        <div class="stat-value">{{ s.members }}</div>
        <div class="stat-title">Members</div></div>
      <div class="report-stat-card"><div class="stat-icon">🗳️</div>
        <div class="stat-value">{{ s.polls }}</div>
        <div class="stat-title">Polls</div>
        <div class="stat-sub">{{ s.votes }} votes</div></div>
      <div class="report-stat-card"><div class="stat-icon">🎯</div>
        <div class="stat-value">{{ s.camps }}</div>
        <div class="stat-title">Campaigns</div></div>
      <div class="report-stat-card"><div class="stat-icon">📅</div>
        <div class="stat-value">{{ s.dues_plans }}</div>
        <div class="stat-title">Dues Periods</div></div>
      <div class="report-stat-card"><div class="stat-icon">💰</div>
        <div class="stat-value">GH₵{{ "%.2f"|format(s.contrib_total) }}</div>
        <div class="stat-title">Contributions</div></div>
      <div class="report-stat-card"><div class="stat-icon">💵</div>
        <div class="stat-value">GH₵{{ "%.2f"|format(s.dues_total) }}</div>
        <div class="stat-title">Dues Collected</div></div>
    </div>

    {% if dues_chart %}
    <div class="report-section">
      <h2>📈 Dues collected per month</h2>
      {{ dues_chart|safe }}
    </div>
    {% endif %}

    {% if member_status_chart %}
    <div class="report-section">
      <h2>👥 Members by status</h2>
      {{ member_status_chart|safe }}
    </div>
    {% endif %}

    <div class="admin-actions">
      <a href="{{ url_for('admin.polls') }}"   class="btn btn-primary">🗳️ Polls</a>
      <a href="{{ url_for('admin.contrib') }}" class="btn btn-primary">🎯 Contributions</a>
      <a href="{{ url_for('admin.dues') }}"    class="btn btn-primary">📅 Dues</a>
      <a href="{{ url_for('admin.members') }}" class="btn btn-primary">👥 Members</a>
      <a href="{{ url_for('admin.admin_users') }}" class="btn btn-secondary">🔐 Admin Users</a>
      <a href="{{ url_for('admin.login_history') }}" class="btn btn-secondary">🔐 Login History</a>
      <a href="{{ url_for('admin.reports') }}" class="btn btn-secondary">📈 Reports</a>
      <a href="{{ url_for('admin.backup') }}"  class="btn btn-secondary">💾 Backup (ZIP)</a>
    </div>
    """, s=stats, dues_chart=dues_chart, member_status_chart=member_status_chart)
    return _page(body)


# ─────────────────────────────────────────────────────────
# POLLS (scheduling + anonymous + unlimited options)
# ─────────────────────────────────────────────────────────
@admin_bp.route('/polls', methods=['GET', 'POST'])
@_admin_required
def polls():
    if request.method == 'POST':
        action = request.form.get('action', 'create')

        if action == 'create':
            title = _sanitize(request.form.get('title', ''), 200)
            desc  = _sanitize(request.form.get('description', ''), 400)
            try:
                n = int(request.form.get('option_count', 2))
            except (TypeError, ValueError):
                n = 2
            n = max(2, min(n, 100))
            opts = [_sanitize(request.form.get(f'option_{i}', ''), 120) for i in range(n)]
            opts = [o for o in opts if o]

            open_at  = _sanitize(request.form.get('open_at', ''), 30)
            close_at = _sanitize(request.form.get('close_at', ''), 30)
            anonymous = 'True' if request.form.get('anonymous') else 'False'

            if title and len(opts) >= 2:
                _insert(T_POLLS, POLLS_FILE, {
                    'poll_id': f"POLL{int(time.time())}_{random.randint(100,999)}",
                    'title': title, 'description': desc,
                    'options_json': json.dumps([{'id': f'opt_{i}', 'text': t}
                                                for i, t in enumerate(opts)]),
                    'created_at': datetime.now().isoformat(),
                    'active': 'True',
                    'open_at': open_at,
                    'close_at': close_at,
                    'anonymous': anonymous,
                })
                flash(f'✅ Poll created with {len(opts)} options.', 'success')
            else:
                flash('Need a title and at least 2 options.', 'danger')

        elif action == 'delete':
            pid = request.form.get('poll_id')
            if pid and _delete_where(T_POLLS, POLLS_FILE, 'poll_id', pid):
                _delete_where(T_VOTES, VOTES_FILE, 'poll_id', pid)
                flash('Poll deleted.', 'success')

        elif action == 'toggle':
            pid = request.form.get('poll_id')
            df = _load(T_POLLS, POLLS_FILE)
            if pid and not df.empty:
                row = df[df['poll_id'] == pid]
                if not row.empty:
                    cur = str(row.iloc[0]['active']).lower() in ['true', '1', 'yes']
                    _update_where(T_POLLS, POLLS_FILE, 'poll_id', pid,
                                  {'active': str(not cur)})
                    flash(f'Poll {"closed" if cur else "re-opened"}.', 'success')

        return redirect(url_for('admin.polls'))

    polls_df = _load(T_POLLS, POLLS_FILE)
    votes_df = _load(T_VOTES, VOTES_FILE)
    member_count = len(_load(T_MEMBERS, MEMBERS_FILE))

    # Date filter
    from_date = _sanitize(request.args.get('from', ''), 10)
    to_date   = _sanitize(request.args.get('to', ''), 10)

    reports = []
    if not polls_df.empty:
        for _, p in polls_df.iterrows():
            created = str(p.get('created_at', ''))[:10]
            if from_date and created < from_date:
                continue
            if to_date and created > to_date:
                continue
            pid = p['poll_id']
            try:
                opts = json.loads(p.get('options_json', '[]'))
            except Exception:
                opts = []
            pv = votes_df[votes_df['poll_id'] == pid] if not votes_df.empty else pd.DataFrame()
            tally = pv['option_id'].value_counts().to_dict() if not pv.empty else {}
            total = len(pv)
            results = [{'text': o['text'], 'votes': tally.get(o['id'], 0),
                        'pct': round(tally.get(o['id'], 0) / total * 100, 1) if total else 0}
                       for o in opts]
            winner = max(results, key=lambda x: x['votes'])['text'] if results and total else None
            reports.append({
                'id': pid, 'title': p['title'],
                'description': p.get('description', ''),
                'active': str(p.get('active', True)).lower() in ['true', '1', 'yes'],
                'anonymous': str(p.get('anonymous', 'False')).lower() == 'true',
                'open_at': p.get('open_at', ''),
                'close_at': p.get('close_at', ''),
                'created_at': created,
                'total': total,
                'option_count': len(opts),
                'turnout': round(total / member_count * 100, 1) if member_count else 0,
                'results': results, 'winner': winner,
                'voters': ([] if str(p.get('anonymous', 'False')).lower() == 'true'
                           else pv[['member_name', 'voted_at']].to_dict('records') if not pv.empty else []),
            })

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🗳️ Polls</h1><p class="subtitle">{{ reports|length }}</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.report', kind='all_polls') }}" class="btn btn-secondary">⬇ All Polls</a>
        <a href="{{ url_for('admin.report', kind='all_votes') }}" class="btn btn-secondary">⬇ Votes</a>
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container">
      <h1>➕ Create a Poll</h1>
      <form method="POST" id="create-poll-form">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="create">
        <input type="hidden" name="option_count" id="option_count_hidden" value="2">

        <div class="form-group"><label>Title *</label>
          <input name="title" required maxlength="200"></div>
        <div class="form-group"><label>Description</label>
          <textarea name="description" maxlength="400"></textarea></div>

        <div class="form-row">
          <div class="form-group"><label>Opens at (optional)</label>
            <input type="datetime-local" name="open_at"></div>
          <div class="form-group"><label>Closes at (optional)</label>
            <input type="datetime-local" name="close_at"></div>
        </div>
        <div class="form-group">
          <label><input type="checkbox" name="anonymous" value="1">
            Anonymous voting (hide voter names)</label>
        </div>

        <div class="form-group">
          <label>Options * (minimum 2)</label>
          <div id="options-wrapper">
            <div style="display:flex;gap:8px;margin-bottom:8px;" class="option-row">
              <input type="text" name="option_0" required maxlength="120"
                     placeholder="Option 1" style="flex:1;padding:12px;border:2px solid #e3e7ee;border-radius:10px;">
              <button type="button" class="option-remove-btn" disabled
                      style="width:36px;border-radius:8px;border:none;background:#ffe7e8;color:#ed1c24;cursor:not-allowed;opacity:0.35;">✕</button>
            </div>
            <div style="display:flex;gap:8px;margin-bottom:8px;" class="option-row">
              <input type="text" name="option_1" required maxlength="120"
                     placeholder="Option 2" style="flex:1;padding:12px;border:2px solid #e3e7ee;border-radius:10px;">
              <button type="button" class="option-remove-btn" disabled
                      style="width:36px;border-radius:8px;border:none;background:#ffe7e8;color:#ed1c24;cursor:not-allowed;opacity:0.35;">✕</button>
            </div>
          </div>
          <div style="display:flex;justify-content:space-between;margin-top:12px;padding-top:12px;border-top:1px dashed #e3e7ee;">
            <button type="button" id="add-option-btn"
                    style="padding:9px 18px;border-radius:10px;border:2px solid #1a3fbf;background:#fff;color:#1a3fbf;font-weight:700;cursor:pointer;">
              ➕ Add another option
            </button>
            <span><span id="option-counter">2</span> options</span>
          </div>
        </div>

        <button class="btn btn-primary btn-full" style="margin-top:1.5rem;">✅ Create Poll</button>
      </form>
    </div>

    <div class="form-container" style="max-width:640px;">
      <h3>Filter by creation date</h3>
      <form method="GET">
        <div class="form-row">
          <div class="form-group"><label>From</label>
            <input type="date" name="from" value="{{ from_date }}"></div>
          <div class="form-group"><label>To</label>
            <input type="date" name="to" value="{{ to_date }}"></div>
        </div>
        <button class="btn btn-primary">Apply Filter</button>
      </form>
    </div>

    {% for p in reports %}
    <div class="poll-report-card">
      <div class="poll-report-header">
        <div>
          <h2>{{ p.title }}
            <span class="status-badge status-{{ 'active' if p.active else 'closed' }}">
              {{ 'Active' if p.active else 'Closed' }}</span>
            {% if p.anonymous %}<span class="status-badge" style="background:#e7ecff;color:#1a3fbf;">Anonymous</span>{% endif %}
          </h2>
          <p>{{ p.description }}</p>
          <p class="poll-meta">
            Created {{ p.created_at }} • {{ p.option_count }} options
            {% if p.open_at %}• Opens {{ p.open_at[:16] }}{% endif %}
            {% if p.close_at %}• Closes {{ p.close_at[:16] }}{% endif %}
          </p>
        </div>
        <div class="poll-totals">
          <div class="poll-total-value">{{ p.total }}</div>
          <div class="poll-total-label">Votes</div>
          <div class="poll-turnout">{{ p.turnout }}%</div>
        </div>
      </div>

      {% for o in p.results %}
      <div class="poll-result-row {% if o.text == p.winner %}winner{% endif %}">
        <div class="result-option-name">{{ o.text }}
          {% if o.text == p.winner %}<span class="winner-badge">🏆</span>{% endif %}</div>
        <div class="result-bar-track"><div class="result-bar-fill" style="width: {{ o.pct }}%"></div></div>
        <div class="result-numbers">
          <span class="result-votes">{{ o.votes }}</span>
          <span class="result-pct">{{ o.pct }}%</span>
        </div>
      </div>
      {% endfor %}

      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:1rem;padding-top:1rem;border-top:1px dashed #e3e7ee;">
        <a href="{{ url_for('admin.report', kind='poll', poll_id=p.id) }}" class="btn btn-small btn-primary">⬇ Report CSV</a>
        <a href="{{ url_for('admin.report_pdf', kind='poll', poll_id=p.id) }}" class="btn btn-small btn-secondary">⬇ Report PDF</a>
        <form method="POST" style="display:inline;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="toggle">
          <input type="hidden" name="poll_id" value="{{ p.id }}">
          <button class="btn btn-small btn-secondary">{{ '🔒 Close' if p.active else '🔓 Re-open' }}</button>
        </form>
        <form method="POST" style="display:inline;" onsubmit="return confirm('Delete this poll?');">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="poll_id" value="{{ p.id }}">
          <button class="btn btn-small btn-primary">🗑️ Delete</button>
        </form>
      </div>
    </div>
    {% else %}
    <p class="empty-state">No polls.</p>
    {% endfor %}

    <script>
      (function(){
        var MIN=2, MAX=100;
        var w = document.getElementById('options-wrapper');
        var add = document.getElementById('add-option-btn');
        var cnt = document.getElementById('option_counter');
        var hidden = document.getElementById('option_count_hidden');
        function refresh(){
          var rows = w.querySelectorAll('.option-row');
          for (var i=0;i<rows.length;i++){
            var inp = rows[i].querySelector('input[type="text"]');
            var rm = rows[i].querySelector('.option-remove-btn');
            inp.name='option_'+i; inp.placeholder='Option '+(i+1);
            if (rm) { rm.disabled = rows.length<=MIN; rm.style.opacity = rm.disabled ? 0.35 : 1; rm.style.cursor = rm.disabled ? 'not-allowed' : 'pointer'; }
          }
          cnt.textContent = rows.length;
          hidden.value = rows.length;
          add.disabled = rows.length>=MAX;
        }
        add.addEventListener('click', function(){
          var rows = w.querySelectorAll('.option-row');
          if (rows.length>=MAX) return;
          var i = rows.length;
          var row = document.createElement('div');
          row.className='option-row';
          row.style.cssText='display:flex;gap:8px;margin-bottom:8px;';
          row.innerHTML = '<input type="text" name="option_'+i+'" maxlength="120" placeholder="Option '+(i+1)+'" style="flex:1;padding:12px;border:2px solid #e3e7ee;border-radius:10px;">'+
            '<button type="button" class="option-remove-btn" style="width:36px;border-radius:8px;border:none;background:#ffe7e8;color:#ed1c24;cursor:pointer;">✕</button>';
          w.appendChild(row);
          refresh();
        });
        w.addEventListener('click', function(e){
          var t = e.target;
          if (!t.classList || !t.classList.contains('option-remove-btn')) return;
          var rows = w.querySelectorAll('.option-row');
          if (rows.length<=MIN) return;
          t.parentNode.remove();
          refresh();
        });
        refresh();
      })();
    </script>
    """, reports=reports, from_date=from_date, to_date=to_date)
    return _page(body)


# ─────────────────────────────────────────────────────────
# CONTRIBUTIONS
# ─────────────────────────────────────────────────────────
@admin_bp.route('/contributions', methods=['GET', 'POST'])
@_admin_required
def contrib():
    if request.method == 'POST':
        action = request.form.get('action', 'create')
        if action == 'create':
            title = _sanitize(request.form.get('title', ''), 200)
            desc  = _sanitize(request.form.get('description', ''), 400)
            try:
                target = float(request.form.get('target_amount', 0) or 0)
            except ValueError:
                target = 0
            if title and target > 0:
                _insert(T_CAMPAIGNS, CAMPAIGNS_FILE, {
                    'campaign_id': f"CAMP{int(time.time())}_{random.randint(100,999)}",
                    'title': title, 'description': desc,
                    'target_amount': target,
                    'created_at': datetime.now().isoformat(),
                    'active': 'True',
                })
                flash(f'Campaign created: "{title}"', 'success')
        elif action == 'delete':
            cid = request.form.get('campaign_id')
            if cid and _delete_where(T_CAMPAIGNS, CAMPAIGNS_FILE, 'campaign_id', cid):
                _delete_where(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE, 'campaign_id', cid)
                flash('Campaign deleted.', 'success')
        elif action == 'toggle':
            cid = request.form.get('campaign_id')
            df = _load(T_CAMPAIGNS, CAMPAIGNS_FILE)
            if cid and not df.empty:
                row = df[df['campaign_id'] == cid]
                if not row.empty:
                    cur = str(row.iloc[0]['active']).lower() in ['true', '1', 'yes']
                    _update_where(T_CAMPAIGNS, CAMPAIGNS_FILE, 'campaign_id', cid,
                                  {'active': str(not cur)})
        return redirect(url_for('admin.contrib'))

    camps = _load(T_CAMPAIGNS, CAMPAIGNS_FILE)
    payments = _load(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE)
    member_count = len(_load(T_MEMBERS, MEMBERS_FILE))

    reports = []
    if not camps.empty:
        for _, c in camps.iterrows():
            cid = c['campaign_id']
            target = float(c.get('target_amount', 0) or 0)
            sub = payments[payments['campaign_id'] == cid] if not payments.empty else pd.DataFrame()
            raised = float(pd.to_numeric(sub['amount'], errors='coerce').fillna(0).sum()) if not sub.empty else 0
            paid_ids = set(sub['member_id'].tolist()) if not sub.empty else set()
            pct = (raised / target * 100) if target else 0
            reports.append({
                'id': cid, 'title': c['title'],
                'description': c.get('description', ''),
                'target': target, 'raised': raised,
                'pct': min(pct, 100), 'raw_pct': round(pct, 1),
                'paid': len(paid_ids),
                'unpaid': member_count - len(paid_ids),
                'active': str(c.get('active', True)).lower() in ['true', '1', 'yes'],
            })

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🎯 Campaigns</h1><p class="subtitle">{{ reports|length }}</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.report', kind='all_campaigns') }}" class="btn btn-secondary">⬇ CSV</a>
        <a href="{{ url_for('admin.report_pdf', kind='all_campaigns') }}" class="btn btn-secondary">⬇ PDF</a>
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container">
      <h1>➕ Create Campaign</h1>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="create">
        <div class="form-group"><label>Title *</label>
          <input name="title" required maxlength="200"></div>
        <div class="form-group"><label>Description</label>
          <textarea name="description" maxlength="400"></textarea></div>
        <div class="form-group"><label>Target (GH₵) *</label>
          <input type="number" step="0.01" name="target_amount" required></div>
        <button class="btn btn-primary btn-full">Create</button>
      </form>
    </div>

    {% for c in reports %}
    <div class="poll-report-card">
      <div class="poll-report-header">
        <div><h2>{{ c.title }}</h2><p>{{ c.description }}</p></div>
        <div class="poll-totals">
          <div class="poll-total-value">GH₵{{ "%.2f"|format(c.raised) }}</div>
          <div class="poll-total-label">of GH₵{{ "%.2f"|format(c.target) }}</div>
          <div class="poll-turnout">{{ c.raw_pct }}%</div>
        </div>
      </div>
      <div class="progress-track">
        <div class="progress-fill {% if c.pct >= 100 %}full{% endif %}"
             style="width: {{ c.pct }}%"></div>
      </div>
      <div class="admin-actions" style="margin-top:1rem;">
        <a href="{{ url_for('admin.report', kind='campaign', campaign_id=c.id) }}" class="btn btn-small btn-primary">⬇ CSV</a>
        <a href="{{ url_for('admin.report_pdf', kind='campaign', campaign_id=c.id) }}" class="btn btn-small btn-secondary">⬇ PDF</a>
        <form method="POST" style="display:inline;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="toggle">
          <input type="hidden" name="campaign_id" value="{{ c.id }}">
          <button class="btn btn-small btn-secondary">{{ '🔒 Close' if c.active else '🔓 Re-open' }}</button>
        </form>
        <form method="POST" style="display:inline;" onsubmit="return confirm('Delete?');">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="campaign_id" value="{{ c.id }}">
          <button class="btn btn-small btn-primary">🗑️ Delete</button>
        </form>
      </div>
    </div>
    {% endfor %}
    """, reports=reports)
    return _page(body)


# ─────────────────────────────────────────────────────────
# DUES
# ─────────────────────────────────────────────────────────
@admin_bp.route('/dues', methods=['GET', 'POST'])
@_admin_required
def dues():
    if request.method == 'POST':
        action = request.form.get('action', 'create')
        if action == 'create':
            month = _sanitize(request.form.get('month', ''), 30)
            year  = _sanitize(request.form.get('year', ''), 10)
            try:
                amount = float(request.form.get('amount', 0) or 0)
            except ValueError:
                amount = 0
            if month and year and amount > 0:
                _insert(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE, {
                    'dues_id': f"DUES{year}{month.upper()}_{random.randint(100,999)}",
                    'month': month, 'year': year, 'amount': amount,
                    'created_at': datetime.now().isoformat(),
                    'active': 'True',
                })
                flash(f'Dues created: {month} {year} — GH₵{amount:.2f}', 'success')
        elif action == 'delete':
            did = request.form.get('dues_id')
            if did and _delete_where(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE, 'dues_id', did):
                _delete_where(T_DUES, DUES_FILE, 'dues_id', did)
                flash('Dues deleted.', 'success')
        elif action == 'toggle':
            did = request.form.get('dues_id')
            df = _load(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE)
            if did and not df.empty:
                row = df[df['dues_id'] == did]
                if not row.empty:
                    cur = str(row.iloc[0]['active']).lower() in ['true', '1', 'yes']
                    _update_where(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE, 'dues_id', did,
                                  {'active': str(not cur)})
        return redirect(url_for('admin.dues'))

    plans = _load(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE)
    payments = _load(T_DUES, DUES_FILE)
    member_count = len(_load(T_MEMBERS, MEMBERS_FILE))

    reports = []
    if not plans.empty:
        for _, d in plans.iterrows():
            did = d['dues_id']
            amount = float(d.get('amount', 0) or 0)
            sub = payments[payments['dues_id'] == did] if not payments.empty else pd.DataFrame()
            collected = float(pd.to_numeric(sub['amount'], errors='coerce').fillna(0).sum()) if not sub.empty else 0
            expected = amount * member_count
            paid_ids = set(sub['member_id'].tolist()) if not sub.empty else set()
            pct = (collected / expected * 100) if expected else 0
            reports.append({
                'id': did, 'month': d.get('month', ''), 'year': d.get('year', ''),
                'amount': amount, 'collected': collected, 'expected': expected,
                'pct': min(pct, 100), 'raw_pct': round(pct, 1),
                'paid': len(paid_ids), 'unpaid': member_count - len(paid_ids),
                'active': str(d.get('active', True)).lower() in ['true', '1', 'yes'],
            })

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>📅 Dues</h1><p class="subtitle">{{ reports|length }}</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.report', kind='all_dues_plans') }}" class="btn btn-secondary">⬇ CSV</a>
        <a href="{{ url_for('admin.report_pdf', kind='all_dues_plans') }}" class="btn btn-secondary">⬇ PDF</a>
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container">
      <h1>➕ Create Dues Period</h1>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="create">
        <div class="form-row">
          <div class="form-group"><label>Month *</label>
            <select name="month" required>
              <option value="">—</option>
              {% for m in months %}<option>{{ m }}</option>{% endfor %}
            </select></div>
          <div class="form-group"><label>Year *</label>
            <input name="year" required placeholder="2026"></div>
        </div>
        <div class="form-group"><label>Amount per member *</label>
          <input type="number" step="0.01" name="amount" required></div>
        <button class="btn btn-primary btn-full">Create</button>
      </form>
    </div>

    {% for d in reports %}
    <div class="poll-report-card">
      <div class="poll-report-header">
        <div><h2>{{ d.month }} {{ d.year }}
          <span class="status-badge status-{{ 'active' if d.active else 'closed' }}">
            {{ 'Open' if d.active else 'Closed' }}</span></h2>
          <p>GH₵{{ "%.2f"|format(d.amount) }} per member</p></div>
        <div class="poll-totals">
          <div class="poll-total-value">GH₵{{ "%.2f"|format(d.collected) }}</div>
          <div class="poll-total-label">of GH₵{{ "%.2f"|format(d.expected) }}</div>
          <div class="poll-turnout">{{ d.raw_pct }}%</div>
        </div>
      </div>
      <div class="progress-track">
        <div class="progress-fill {% if d.pct >= 100 %}full{% endif %}"
             style="width: {{ d.pct }}%"></div>
      </div>
      <div class="admin-actions" style="margin-top:1rem;">
        <a href="{{ url_for('admin.report', kind='dues_plan', dues_id=d.id) }}" class="btn btn-small btn-primary">⬇ CSV</a>
        <a href="{{ url_for('admin.report_pdf', kind='dues_plan', dues_id=d.id) }}" class="btn btn-small btn-secondary">⬇ PDF</a>
        <form method="POST" style="display:inline;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="toggle">
          <input type="hidden" name="dues_id" value="{{ d.id }}">
          <button class="btn btn-small btn-secondary">{{ '🔒 Close' if d.active else '🔓 Re-open' }}</button>
        </form>
        <form method="POST" style="display:inline;" onsubmit="return confirm('Delete?');">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="dues_id" value="{{ d.id }}">
          <button class="btn btn-small btn-primary">🗑️ Delete</button>
        </form>
      </div>
    </div>
    {% endfor %}
    """, reports=reports, months=MONTHS)
    return _page(body)


# ─────────────────────────────────────────────────────────
# MEMBERS (with search, bulk actions, roles, suspension, CSV import)
# ─────────────────────────────────────────────────────────
@admin_bp.route('/members', methods=['GET', 'POST'])
@_admin_required
def members():
    if request.method == 'POST':
        action = request.form.get('action', 'add')

        if action == 'add':
            first_name  = _sanitize(request.form.get('first_name', ''), 120)
            middle_name = _sanitize(request.form.get('middle_name', ''), 120)
            last_name   = _sanitize(request.form.get('last_name', ''), 120)
            email       = _sanitize(request.form.get('email', ''), 120).lower()
            if first_name and last_name and email:
                from werkzeug.security import generate_password_hash
                full_name = _build_full_name(first_name, middle_name, last_name)
                _insert(T_MEMBERS, MEMBERS_FILE, {
                    'member_id':         f"MEM{int(time.time())}{random.randint(100,999)}",
                    'title':             _sanitize(request.form.get('title', ''), 20),
                    'first_name':        first_name,
                    'middle_name':       middle_name,
                    'last_name':         last_name,
                    'full_name':         full_name,
                    'dob_day':           _sanitize(request.form.get('dob_day', ''), 2),
                    'dob_month':         _sanitize(request.form.get('dob_month', ''), 20),
                    'dob_year':          _sanitize(request.form.get('dob_year', ''), 4),
                    'email':             email,
                    'phone':             _sanitize(request.form.get('phone', ''), 40),
                    'house':             _sanitize(request.form.get('house', ''), 60),
                    'emergency_contact': _sanitize(request.form.get('emergency_contact', ''), 200),
                    'job_title':         _sanitize(request.form.get('job_title', ''), 120),
                    'industry':          _sanitize(request.form.get('industry', ''), 120),
                    'password_hash':     generate_password_hash('changeme123'),
                    'registered_at':     datetime.now().isoformat(),
                    'status':            'active',
                    'role':              'member',
                    'totp_secret':       '',
                    'totp_enabled':      'False',
                })
                flash(f'Member added: {full_name}', 'success')

        elif action == 'edit':
            mid = request.form.get('member_id')
            first_name  = _sanitize(request.form.get('first_name', ''), 120)
            middle_name = _sanitize(request.form.get('middle_name', ''), 120)
            last_name   = _sanitize(request.form.get('last_name', ''), 120)
            updates = {
                'title':             _sanitize(request.form.get('title', ''), 20),
                'first_name':        first_name,
                'middle_name':       middle_name,
                'last_name':         last_name,
                'full_name':         _build_full_name(first_name, middle_name, last_name),
                'email':             _sanitize(request.form.get('email', ''), 120).lower(),
                'phone':             _sanitize(request.form.get('phone', ''), 40),
                'dob_day':           _sanitize(request.form.get('dob_day', ''), 2),
                'dob_month':         _sanitize(request.form.get('dob_month', ''), 20),
                'dob_year':          _sanitize(request.form.get('dob_year', ''), 4),
                'house':             _sanitize(request.form.get('house', ''), 60),
                'emergency_contact': _sanitize(request.form.get('emergency_contact', ''), 200),
                'job_title':         _sanitize(request.form.get('job_title', ''), 120),
                'industry':          _sanitize(request.form.get('industry', ''), 120),
                'status':            _sanitize(request.form.get('status', 'active'), 20),
                'role':              _sanitize(request.form.get('role', 'member'), 20),
            }
            if mid and _update_where(T_MEMBERS, MEMBERS_FILE, 'member_id', mid, updates):
                flash('Member updated.', 'success')

        elif action == 'delete':
            mid = request.form.get('member_id')
            if mid and _delete_where(T_MEMBERS, MEMBERS_FILE, 'member_id', mid):
                flash('Member deleted.', 'success')

        elif action == 'bulk_delete':
            ids = request.form.getlist('member_ids')
            count = 0
            for mid in ids:
                if _delete_where(T_MEMBERS, MEMBERS_FILE, 'member_id', mid):
                    count += 1
            flash(f'{count} member(s) deleted.', 'success')

        elif action == 'import':
            f = request.files.get('csv_file')
            if not f or not f.filename:
                flash('Please choose a CSV file.', 'danger')
                return redirect(url_for('admin.members'))
            try:
                df = pd.read_csv(f, dtype=str).fillna('')
                added = 0
                from werkzeug.security import generate_password_hash
                for _, row in df.iterrows():
                    email = str(row.get('email', '')).strip().lower()
                    if not email or '@' not in email:
                        continue
                    existing = _load(T_MEMBERS, MEMBERS_FILE)
                    if not existing.empty and email in existing['email'].str.lower().values:
                        continue
                    fn = str(row.get('first_name', '')).strip()
                    ln = str(row.get('last_name', '')).strip()
                    mn = str(row.get('middle_name', '')).strip()
                    if not (fn and ln):
                        continue
                    _insert(T_MEMBERS, MEMBERS_FILE, {
                        'member_id':         f"MEM{int(time.time())}{random.randint(100,999)}",
                        'title':             str(row.get('title', '')).strip(),
                        'first_name':        fn,
                        'middle_name':       mn,
                        'last_name':         ln,
                        'full_name':         _build_full_name(fn, mn, ln),
                        'dob_day':           str(row.get('dob_day', '')).strip(),
                        'dob_month':         str(row.get('dob_month', '')).strip(),
                        'dob_year':          str(row.get('dob_year', '')).strip(),
                        'email':             email,
                        'phone':             str(row.get('phone', '')).strip(),
                        'house':             str(row.get('house', '')).strip(),
                        'emergency_contact': str(row.get('emergency_contact', '')).strip(),
                        'job_title':         str(row.get('job_title', '')).strip(),
                        'industry':          str(row.get('industry', '')).strip(),
                        'password_hash':     generate_password_hash(
                            str(row.get('password', '') or 'changeme123')),
                        'registered_at':     datetime.now().isoformat(),
                        'status':            'active',
                        'role':              'member',
                        'totp_secret':       '',
                        'totp_enabled':      'False',
                    })
                    added += 1
                flash(f'Imported {added} member(s).', 'success')
            except Exception as e:
                flash(f'Import failed: {e}', 'danger')

        return redirect(url_for('admin.members'))

    q = _sanitize(request.args.get('q', ''), 100).lower()
    df = _load(T_MEMBERS, MEMBERS_FILE)
    rows = df.to_dict('records') if not df.empty else []
    for r in rows:
        r.pop('password_hash', None)
    if q:
        rows = [r for r in rows if q in (
            (r.get('full_name','') + ' ' + r.get('email','') + ' ' +
             r.get('phone','') + ' ' + r.get('house','')).lower()
        )]

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>👥 Members ({{ rows|length }})</h1></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.report', kind='all_members') }}" class="btn btn-secondary">⬇ CSV</a>
        <a href="{{ url_for('admin.report_pdf', kind='all_members') }}" class="btn btn-secondary">⬇ PDF</a>
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container" style="max-width:640px;">
      <h3>Search</h3>
      <form method="GET">
        <div class="form-group" style="display:flex;gap:0.5rem;">
          <input name="q" value="{{ q }}" placeholder="Name, email, house...">
          <button class="btn btn-primary">Search</button>
        </div>
      </form>
    </div>

    <div class="form-container">
      <h3>📥 Bulk Import (CSV)</h3>
      <p class="form-subtitle">
        Columns: first_name, last_name, middle_name, email, phone, house,
        dob_day, dob_month, dob_year, emergency_contact, job_title, industry
      </p>
      <form method="POST" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="import">
        <div class="form-group"><input type="file" name="csv_file" accept=".csv" required></div>
        <button class="btn btn-primary">Import</button>
      </form>
    </div>

    <div class="form-container">
      <h3>➕ Add Member</h3>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="add">
        <div class="form-row">
          <div class="form-group"><label>First Name *</label>
            <input name="first_name" required></div>
          <div class="form-group"><label>Middle Name</label>
            <input name="middle_name"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Last Name *</label>
            <input name="last_name" required></div>
          <div class="form-group"><label>Email *</label>
            <input type="email" name="email" required></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Phone</label>
            <input name="phone"></div>
          <div class="form-group"><label>House</label>
            <input name="house"></div>
        </div>
        <button class="btn btn-primary btn-full">Add</button>
      </form>
    </div>

    <form method="POST">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <input type="hidden" name="action" value="bulk_delete">
      <div class="table-wrapper">
        <table class="report-table full-width">
          <thead><tr>
            <th style="width:36px;"><input type="checkbox" id="check-all"></th>
            <th>Name</th><th>Email</th><th>House</th>
            <th>Role</th><th>Status</th><th>Actions</th>
          </tr></thead>
          <tbody>
          {% for m in rows %}
            <tr>
              <td><input type="checkbox" name="member_ids" value="{{ m.member_id }}"></td>
              <td><strong>{{ m.get('title','') }} {{ m.get('first_name') or m.get('full_name','') }} {{ m.get('last_name','') }}</strong></td>
              <td>{{ m.get('email','') }}</td>
              <td>{{ m.get('house','') or '—' }}</td>
              <td>{{ m.get('role','member') }}</td>
              <td>{{ m.get('status','active') }}</td>
              <td>
                <details>
                  <summary style="cursor:pointer;color:var(--presec-blue);font-weight:700;">Edit</summary>
                  <form method="POST" style="margin-top:0.5rem;">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="action" value="edit">
                    <input type="hidden" name="member_id" value="{{ m.member_id }}">
                    <div class="form-group"><label>First</label>
                      <input name="first_name" value="{{ m.get('first_name','') }}"></div>
                    <div class="form-group"><label>Middle</label>
                      <input name="middle_name" value="{{ m.get('middle_name','') }}"></div>
                    <div class="form-group"><label>Last</label>
                      <input name="last_name" value="{{ m.get('last_name','') }}"></div>
                    <div class="form-group"><label>Email</label>
                      <input name="email" value="{{ m.get('email','') }}"></div>
                    <div class="form-group"><label>Phone</label>
                      <input name="phone" value="{{ m.get('phone','') }}"></div>
                    <div class="form-group"><label>House</label>
                      <input name="house" value="{{ m.get('house','') }}"></div>
                    <div class="form-group"><label>Status</label>
                      <select name="status">
                        <option value="active" {% if m.get('status','active')=='active' %}selected{% endif %}>active</option>
                        <option value="suspended" {% if m.get('status')=='suspended' %}selected{% endif %}>suspended</option>
                      </select></div>
                    <div class="form-group"><label>Role</label>
                      <select name="role">
                        {% for r in ['member','treasurer','secretary','admin'] %}
                        <option {% if m.get('role','member')==r %}selected{% endif %}>{{ r }}</option>
                        {% endfor %}
                      </select></div>
                    <button class="btn btn-small btn-primary">Save</button>
                  </form>
                  <form method="POST" style="margin-top:0.5rem;" onsubmit="return confirm('Delete?');">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="member_id" value="{{ m.member_id }}">
                    <button class="btn btn-small btn-primary">🗑️ Delete</button>
                  </form>
                </details>
              </td>
            </tr>
          {% else %}
            <tr><td colspan="7" class="empty-state">No members.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
      {% if rows %}
      <button class="btn btn-primary" style="margin-top:1rem;"
              onclick="return confirm('Delete all selected members?');">
        🗑️ Delete Selected
      </button>
      {% endif %}
    </form>

    <script>
      document.getElementById('check-all').addEventListener('change', function(e){
        document.querySelectorAll('input[name="member_ids"]').forEach(function(c){
          c.checked = e.target.checked;
        });
      });
    </script>
    """, rows=rows, q=q)
    return _page(body)


# ─────────────────────────────────────────────────────────
# ADMIN USERS (individual accounts + 2FA)
# ─────────────────────────────────────────────────────────
@admin_bp.route('/admin-users', methods=['GET', 'POST'])
@_admin_required
def admin_users():
    csv_path = os.path.join(DATA_DIR, 'admin_users.csv')
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            email = _sanitize(request.form.get('email', ''), 120).lower()
            name  = _sanitize(request.form.get('full_name', ''), 120)
            pwd   = request.form.get('password', '')
            role  = _sanitize(request.form.get('role', 'admin'), 20)
            if email and len(pwd) >= 8:
                _insert(T_ADMIN_USERS, csv_path, {
                    'admin_id': f"ADM{int(time.time())}{random.randint(100,999)}",
                    'email': email,
                    'full_name': name,
                    'password_hash': generate_password_hash(pwd),
                    'role': role,
                    'created_at': datetime.now().isoformat(),
                    'last_login': '',
                    'active': 'True',
                    'totp_secret': '',
                    'totp_enabled': 'False',
                })
                flash(f'Admin added: {email}', 'success')
        elif action == 'delete':
            aid = request.form.get('admin_id')
            if aid and _delete_where(T_ADMIN_USERS, csv_path, 'admin_id', aid):
                flash('Admin removed.', 'success')
        return redirect(url_for('admin.admin_users'))

    df = _load(T_ADMIN_USERS, csv_path)
    rows = df.to_dict('records') if not df.empty else []
    for r in rows:
        r.pop('password_hash', None)
        r.pop('totp_secret', None)

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🔐 Admin Accounts</h1></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container">
      <h3>➕ Add Admin</h3>
      <p class="form-subtitle">Each admin has their own login, tracked in history</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="add">
        <div class="form-row">
          <div class="form-group"><label>Full Name</label>
            <input name="full_name" required></div>
          <div class="form-group"><label>Email *</label>
            <input type="email" name="email" required></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Password * (min 8)</label>
            <input type="password" name="password" required minlength="8"></div>
          <div class="form-group"><label>Role</label>
            <select name="role">
              <option value="admin">admin</option>
              <option value="treasurer">treasurer</option>
              <option value="secretary">secretary</option>
            </select></div>
        </div>
        <button class="btn btn-primary btn-full">Add Admin</button>
      </form>
    </div>

    <div class="table-wrapper">
      <table class="report-table full-width">
        <thead><tr>
          <th>Name</th><th>Email</th><th>Role</th>
          <th>Last Login</th><th>Actions</th>
        </tr></thead>
        <tbody>
        {% for r in rows %}
        <tr>
          <td><strong>{{ r.get('full_name','') }}</strong></td>
          <td>{{ r.get('email','') }}</td>
          <td>{{ r.get('role','admin') }}</td>
          <td>{{ r.get('last_login','')[:19] or 'Never' }}</td>
          <td>
            <form method="POST" onsubmit="return confirm('Remove this admin?');">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="admin_id" value="{{ r.admin_id }}">
              <button class="btn btn-small btn-primary">🗑️ Remove</button>
            </form>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="5" class="empty-state">No individual admins yet.</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    """, rows=rows)
    return _page(body)


# ─────────────────────────────────────────────────────────
# LOGIN HISTORY (admin view)
# ─────────────────────────────────────────────────────────
@admin_bp.route('/login-history')
@_admin_required
def login_history():
    rows = sb.fetch_all(T_LOGIN_HISTORY)[-500:]
    rows = list(reversed(rows))

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🔐 Login History</h1>
      <p class="subtitle">Last 500 events (all accounts)</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="table-wrapper">
      <table class="report-table full-width">
        <thead><tr>
          <th>When</th><th>Type</th><th>Subject</th>
          <th>IP</th><th>Result</th><th>Device</th>
        </tr></thead>
        <tbody>
        {% for r in rows %}
        <tr>
          <td>{{ r.happened_at[:19] }}</td>
          <td>{{ r.subject_type }}</td>
          <td>{{ r.subject_id or '—' }}</td>
          <td>{{ r.ip_address }}</td>
          <td>{{ '✅ Success' if r.success == 'True' else '❌ Failed' }}</td>
          <td style="font-size:0.78rem;color:#666;">{{ r.user_agent[:60] }}</td>
        </tr>
        {% else %}
        <tr><td colspan="6" class="empty-state">No login history.</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    """, rows=rows)
    return _page(body)


# ═══════════════════════════════════════════════════════════
# REPORTS HUB (with PDF buttons)
# ═══════════════════════════════════════════════════════════
@admin_bp.route('/reports')
@_admin_required
def reports():
    members = _load(T_MEMBERS, MEMBERS_FILE)
    contrib = _load(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE)
    dues    = _load(T_DUES, DUES_FILE)
    votes   = _load(T_VOTES, VOTES_FILE)
    polls   = _load(T_POLLS, POLLS_FILE)

    def _sum(df):
        if df.empty or 'amount' not in df.columns:
            return 0.0
        return float(pd.to_numeric(df['amount'], errors='coerce').fillna(0).sum())

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>📈 Reports</h1><p class="subtitle">CSV and PDF downloads</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.backup') }}" class="btn btn-primary">💾 Full Backup</a>
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="report-stats-grid">
      <div class="report-stat-card"><div class="stat-icon">👥</div>
        <div class="stat-value">{{ member_count }}</div>
        <div class="stat-title">Members</div></div>
      <div class="report-stat-card"><div class="stat-icon">🎯</div>
        <div class="stat-value">GH₵{{ "%.2f"|format(contrib_total) }}</div>
        <div class="stat-title">Contributions</div></div>
      <div class="report-stat-card"><div class="stat-icon">📅</div>
        <div class="stat-value">GH₵{{ "%.2f"|format(dues_total) }}</div>
        <div class="stat-title">Dues</div></div>
      <div class="report-stat-card"><div class="stat-icon">🗳️</div>
        <div class="stat-value">{{ votes_count }}</div>
        <div class="stat-title">Votes</div></div>
    </div>

    <div class="report-section">
      <h2>🗳️ Voting</h2>
      <div class="report-cards-grid">
        <div class="report-card"><h3>All Polls</h3>
          <a href="{{ url_for('admin.report', kind='all_polls') }}" class="btn btn-primary">⬇ CSV</a>
          <a href="{{ url_for('admin.report_pdf', kind='all_polls') }}" class="btn btn-secondary">⬇ PDF</a></div>
        <div class="report-card"><h3>All Votes</h3>
          <a href="{{ url_for('admin.report', kind='all_votes') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Turnout</h3>
          <a href="{{ url_for('admin.report', kind='turnout') }}" class="btn btn-primary">⬇ CSV</a></div>
      </div>
    </div>

    <div class="report-section">
      <h2>📅 Dues</h2>
      <div class="report-cards-grid">
        <div class="report-card"><h3>All Dues Periods</h3>
          <a href="{{ url_for('admin.report', kind='all_dues_plans') }}" class="btn btn-primary">⬇ CSV</a>
          <a href="{{ url_for('admin.report_pdf', kind='all_dues_plans') }}" class="btn btn-secondary">⬇ PDF</a></div>
        <div class="report-card"><h3>All Dues Payments</h3>
          <a href="{{ url_for('admin.report', kind='all_dues') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Outstanding</h3>
          <a href="{{ url_for('admin.report', kind='outstanding_dues') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Top Payers</h3>
          <a href="{{ url_for('admin.report', kind='top_dues_payers') }}" class="btn btn-primary">⬇ CSV</a></div>
      </div>
    </div>

    <div class="report-section">
      <h2>🎯 Contributions</h2>
      <div class="report-cards-grid">
        <div class="report-card"><h3>All Campaigns</h3>
          <a href="{{ url_for('admin.report', kind='all_campaigns') }}" class="btn btn-primary">⬇ CSV</a>
          <a href="{{ url_for('admin.report_pdf', kind='all_campaigns') }}" class="btn btn-secondary">⬇ PDF</a></div>
        <div class="report-card"><h3>All Contributions</h3>
          <a href="{{ url_for('admin.report', kind='all_contributions') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Outstanding</h3>
          <a href="{{ url_for('admin.report', kind='outstanding_contribs') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Top Contributors</h3>
          <a href="{{ url_for('admin.report', kind='top_contributors') }}" class="btn btn-primary">⬇ CSV</a></div>
      </div>
    </div>

    <div class="report-section">
      <h2>👥 Membership</h2>
      <div class="report-cards-grid">
        <div class="report-card"><h3>All Members</h3>
          <a href="{{ url_for('admin.report', kind='all_members') }}" class="btn btn-primary">⬇ CSV</a>
          <a href="{{ url_for('admin.report_pdf', kind='all_members') }}" class="btn btn-secondary">⬇ PDF</a></div>
        <div class="report-card"><h3>Full Profiles</h3>
          <a href="{{ url_for('admin.report', kind='members_full_profile') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>By House</h3>
          <a href="{{ url_for('admin.report', kind='members_by_house') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>By Industry</h3>
          <a href="{{ url_for('admin.report', kind='members_by_industry') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>By Job Title</h3>
          <a href="{{ url_for('admin.report', kind='members_by_job') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Inactive</h3>
          <a href="{{ url_for('admin.report', kind='inactive_members') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Contacts</h3>
          <a href="{{ url_for('admin.report', kind='contact_directory') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Birthdays</h3>
          <form method="GET" action="{{ url_for('admin.report', kind='birthdays') }}">
            <select name="month" style="margin-bottom:0.5rem;">
              <option value="">All months</option>
              {% for m in months %}<option>{{ m }}</option>{% endfor %}
            </select>
            <button class="btn btn-primary">⬇ CSV</button>
          </form>
        </div>
      </div>
    </div>

    <div class="report-section">
      <h2>📊 Combined</h2>
      <div class="report-cards-grid">
        <div class="report-card"><h3>Master Financial</h3>
          <a href="{{ url_for('admin.report', kind='master_financial') }}" class="btn btn-primary">⬇ CSV</a></div>
        <div class="report-card"><h3>Executive Summary</h3>
          <a href="{{ url_for('admin.report', kind='executive_summary') }}" class="btn btn-primary">⬇ CSV</a>
          <a href="{{ url_for('admin.report_pdf', kind='executive_summary') }}" class="btn btn-secondary">⬇ PDF</a></div>
      </div>
    </div>
    """,
    member_count=len(members), contrib_total=_sum(contrib),
    dues_total=_sum(dues), votes_count=len(votes), months=MONTHS)
    return _page(body)


# ═══════════════════════════════════════════════════════════
# REPORT ROUTER (CSV)
# ═══════════════════════════════════════════════════════════
@admin_bp.route('/report/<kind>')
@_admin_required
def report(kind):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    members        = _load(T_MEMBERS, MEMBERS_FILE)
    polls          = _load(T_POLLS, POLLS_FILE)
    votes          = _load(T_VOTES, VOTES_FILE)
    contribs       = _load(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE)
    campaigns      = _load(T_CAMPAIGNS, CAMPAIGNS_FILE)
    dues_payments  = _load(T_DUES, DUES_FILE)
    dues_plans     = _load(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE)

    from_date = _sanitize(request.args.get('from', ''), 10)
    to_date   = _sanitize(request.args.get('to', ''), 10)

    def _amt(df, col='amount'):
        if df.empty or col not in df.columns:
            return 0.0
        return float(pd.to_numeric(df[col], errors='coerce').fillna(0).sum())

    def _records(df):
        if df.empty:
            return []
        if from_date and 'created_at' in df.columns:
            df = df[df['created_at'].str[:10] >= from_date]
        if to_date and 'created_at' in df.columns:
            df = df[df['created_at'].str[:10] <= to_date]
        return df.to_dict('records')

    if kind == 'all_polls':
        rows = []
        mc = len(members)
        for _, p in polls.iterrows():
            pid = p['poll_id']
            pv = votes[votes['poll_id'] == pid] if not votes.empty else pd.DataFrame()
            try:
                opts = json.loads(p.get('options_json', '[]'))
            except Exception:
                opts = []
            tally = pv['option_id'].value_counts().to_dict() if not pv.empty else {}
            winner = ''
            if tally and opts:
                top_id = max(tally, key=tally.get)
                for o in opts:
                    if o['id'] == top_id:
                        winner = o['text']; break
            rows.append({
                'poll_id': pid, 'title': p['title'],
                'created_at': p.get('created_at', ''),
                'option_count': len(opts), 'total_votes': len(pv),
                'turnout_pct': round(len(pv) / mc * 100, 1) if mc else 0,
                'winner': winner,
                'anonymous': p.get('anonymous', 'False'),
                'open_at': p.get('open_at', ''),
                'close_at': p.get('close_at', ''),
            })
        return _csv_response(rows, f'all_polls_{ts}.csv')

    if kind == 'poll':
        poll_id = request.args.get('poll_id', '')
        p = polls[polls['poll_id'] == poll_id] if not polls.empty else pd.DataFrame()
        if p.empty:
            flash('Poll not found.', 'danger'); return redirect(url_for('admin.reports'))
        p = p.iloc[0]
        try:
            opts = json.loads(p.get('options_json', '[]'))
        except Exception:
            opts = []
        pv = votes[votes['poll_id'] == poll_id] if not votes.empty else pd.DataFrame()
        tally = pv['option_id'].value_counts().to_dict() if not pv.empty else {}
        total = len(pv)
        rows = []
        for o in opts:
            c = tally.get(o['id'], 0)
            rows.append({
                'poll_id': poll_id, 'title': p['title'],
                'option_text': o['text'], 'votes': c,
                'pct': round(c / total * 100, 2) if total else 0,
            })
        return _csv_response(rows, f'poll_{poll_id}_{ts}.csv')

    if kind == 'all_votes':
        rows = _records(votes)
        poll_titles = {r['poll_id']: r['title'] for _, r in polls.iterrows()} if not polls.empty else {}
        for r in rows:
            r['poll_title'] = poll_titles.get(r.get('poll_id', ''), '')
        return _csv_response(rows, f'all_votes_{ts}.csv')

    if kind == 'turnout':
        mc = len(members)
        rows = []
        for _, p in polls.iterrows():
            pid = p['poll_id']
            pv = votes[votes['poll_id'] == pid] if not votes.empty else pd.DataFrame()
            voters = set(pv['member_id'].tolist()) if not pv.empty else set()
            rows.append({
                'poll_id': pid, 'poll_title': p['title'],
                'total_members': mc, 'voted': len(voters),
                'did_not_vote': mc - len(voters),
                'turnout_pct': round(len(voters) / mc * 100, 1) if mc else 0,
            })
        return _csv_response(rows, f'turnout_{ts}.csv')

    if kind == 'all_dues_plans':
        mc = len(members)
        rows = []
        for _, d in dues_plans.iterrows():
            did = d['dues_id']
            amount = float(d.get('amount', 0) or 0)
            paid = dues_payments[dues_payments['dues_id'] == did] if not dues_payments.empty else pd.DataFrame()
            collected = _amt(paid)
            expected = amount * mc
            paid_ids = set(paid['member_id'].tolist()) if not paid.empty else set()
            rows.append({
                'dues_id': did, 'month': d.get('month', ''), 'year': d.get('year', ''),
                'amount_per_member': amount, 'total_expected': expected,
                'total_collected': collected, 'outstanding': expected - collected,
                'collection_pct': round(collected / expected * 100, 1) if expected else 0,
                'paid_count': len(paid_ids), 'unpaid_count': mc - len(paid_ids),
            })
        return _csv_response(rows, f'all_dues_plans_{ts}.csv')

    if kind == 'dues_plan':
        dues_id = request.args.get('dues_id', '')
        paid = dues_payments[dues_payments['dues_id'] == dues_id] if not dues_payments.empty else pd.DataFrame()
        return _csv_response(_records(paid), f'dues_plan_{dues_id}_{ts}.csv')

    if kind == 'all_dues':
        return _csv_response(_records(dues_payments), f'all_dues_{ts}.csv')

    if kind == 'outstanding_dues':
        mc = len(members)
        rows = []
        for _, d in dues_plans.iterrows():
            did = d['dues_id']
            if str(d.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            paid_ids = set(dues_payments[dues_payments['dues_id'] == did]['member_id'].tolist()) if not dues_payments.empty else set()
            unpaid = members[~members['member_id'].isin(paid_ids)] if not members.empty else pd.DataFrame()
            for _, m in unpaid.iterrows():
                rows.append({
                    'dues_id': did, 'month': d.get('month', ''), 'year': d.get('year', ''),
                    'member_name': m.get('full_name', ''),
                    'email': m.get('email', ''), 'phone': m.get('phone', ''),
                })
        return _csv_response(rows, f'outstanding_dues_{ts}.csv')

    if kind == 'top_dues_payers':
        if dues_payments.empty:
            return _csv_response([], f'top_dues_payers_{ts}.csv')
        df = dues_payments.copy()
        df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
        g = df.groupby(['member_id', 'member_name'])['amount'].sum().reset_index()
        g = g.sort_values('amount', ascending=False)
        rows = []
        for i, r in enumerate(g.to_dict('records'), 1):
            r['rank'] = i; r['total_paid'] = r.pop('amount')
            rows.append(r)
        return _csv_response(rows, f'top_dues_payers_{ts}.csv')

    if kind == 'all_campaigns':
        mc = len(members)
        rows = []
        for _, c in campaigns.iterrows():
            cid = c['campaign_id']
            target = float(c.get('target_amount', 0) or 0)
            sub = contribs[contribs['campaign_id'] == cid] if not contribs.empty else pd.DataFrame()
            raised = _amt(sub)
            paid_ids = set(sub['member_id'].tolist()) if not sub.empty else set()
            rows.append({
                'campaign_id': cid, 'title': c['title'],
                'target': target, 'raised': raised,
                'remaining': max(target - raised, 0),
                'funded_pct': round(raised / target * 100, 1) if target else 0,
                'paid_count': len(paid_ids), 'unpaid_count': mc - len(paid_ids),
            })
        return _csv_response(rows, f'all_campaigns_{ts}.csv')

    if kind == 'campaign':
        cid = request.args.get('campaign_id', '')
        sub = contribs[contribs['campaign_id'] == cid] if not contribs.empty else pd.DataFrame()
        return _csv_response(_records(sub), f'campaign_{cid}_{ts}.csv')

    if kind == 'all_contributions':
        return _csv_response(_records(contribs), f'all_contributions_{ts}.csv')

    if kind == 'outstanding_contribs':
        rows = []
        for _, c in campaigns.iterrows():
            cid = c['campaign_id']
            if str(c.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            paid_ids = set(contribs[contribs['campaign_id'] == cid]['member_id'].tolist()) if not contribs.empty else set()
            unpaid = members[~members['member_id'].isin(paid_ids)] if not members.empty else pd.DataFrame()
            for _, m in unpaid.iterrows():
                rows.append({
                    'campaign_id': cid, 'campaign_title': c['title'],
                    'member_name': m.get('full_name', ''),
                    'email': m.get('email', ''), 'phone': m.get('phone', ''),
                })
        return _csv_response(rows, f'outstanding_contribs_{ts}.csv')

    if kind == 'top_contributors':
        if contribs.empty:
            return _csv_response([], f'top_contributors_{ts}.csv')
        df = contribs.copy()
        df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
        g = df.groupby(['member_id', 'member_name'])['amount'].sum().reset_index()
        g = g.sort_values('amount', ascending=False)
        rows = []
        for i, r in enumerate(g.to_dict('records'), 1):
            r['rank'] = i; r['total_contributed'] = r.pop('amount')
            rows.append(r)
        return _csv_response(rows, f'top_contributors_{ts}.csv')

    if kind == 'all_members':
        df = members.copy()
        if 'password_hash' in df.columns:
            df = df.drop(columns=['password_hash'])
        return _csv_response(_records(df), f'all_members_{ts}.csv')

    if kind == 'members_full_profile':
        df = members.copy()
        if 'password_hash' in df.columns:
            df = df.drop(columns=['password_hash'])
        return _csv_response(_records(df), f'members_full_profile_{ts}.csv')

    if kind == 'members_by_house':
        df = members.copy()
        df['house'] = df['house'].replace('', 'Not Specified').fillna('Not Specified')
        g = df.groupby('house').size().reset_index(name='count')
        g = g.sort_values('count', ascending=False)
        rows = []
        for _, r in g.iterrows():
            names = df[df['house'] == r['house']]['full_name'].tolist()
            rows.append({'house': r['house'], 'count': r['count'], 'members': '; '.join(names)})
        return _csv_response(rows, f'members_by_house_{ts}.csv')

    if kind == 'members_by_year':
        df = members.copy()
        if df.empty:
            return _csv_response([], f'members_by_year_{ts}.csv')
        df['reg_month'] = df['registered_at'].str[:7]
        g = df.groupby('reg_month').size().reset_index(name='count')
        g = g.sort_values('reg_month', ascending=False)
        rows = []
        for _, r in g.iterrows():
            names = df[df['reg_month'] == r['reg_month']]['full_name'].tolist()
            rows.append({'month': r['reg_month'], 'count': r['count'], 'members': '; '.join(names)})
        return _csv_response(rows, f'members_by_year_{ts}.csv')

    if kind == 'inactive_members':
        voter_ids = set(votes['member_id'].tolist()) if not votes.empty else set()
        payer_ids = set(dues_payments['member_id'].tolist()) if not dues_payments.empty else set()
        contributor_ids = set(contribs['member_id'].tolist()) if not contribs.empty else set()
        active_ids = voter_ids | payer_ids | contributor_ids
        inactive = members[~members['member_id'].isin(active_ids)] if not members.empty else pd.DataFrame()
        if 'password_hash' in inactive.columns:
            inactive = inactive.drop(columns=['password_hash'])
        return _csv_response(_records(inactive), f'inactive_members_{ts}.csv')

    if kind == 'contact_directory':
        cols = ['title','first_name','middle_name','last_name','email','phone','house']
        cols = [c for c in cols if c in members.columns]
        return _csv_response(_records(members[cols]) if not members.empty else [],
                             f'contact_directory_{ts}.csv')

    if kind == 'members_by_industry':
        df = members.copy()
        df['industry'] = df['industry'].replace('', 'Not Specified').fillna('Not Specified')
        g = df.groupby('industry').size().reset_index(name='count')
        g = g.sort_values('count', ascending=False)
        rows = []
        for _, r in g.iterrows():
            names = df[df['industry'] == r['industry']]['full_name'].tolist()
            rows.append({'industry': r['industry'], 'count': r['count'], 'members': '; '.join(names)})
        return _csv_response(rows, f'members_by_industry_{ts}.csv')

    if kind == 'members_by_job':
        df = members.copy()
        df['job_title'] = df['job_title'].replace('', 'Not Specified').fillna('Not Specified')
        g = df.groupby('job_title').size().reset_index(name='count')
        g = g.sort_values('count', ascending=False)
        rows = []
        for _, r in g.iterrows():
            names = df[df['job_title'] == r['job_title']]['full_name'].tolist()
            rows.append({'job_title': r['job_title'], 'count': r['count'], 'members': '; '.join(names)})
        return _csv_response(rows, f'members_by_job_{ts}.csv')

    if kind == 'birthdays':
        month = request.args.get('month', '')
        df = members.copy()
        if month:
            df = df[df['dob_month'].str.lower() == month.lower()]
        df = df[df['dob_month'].astype(str).str.strip() != '']
        rows = []
        for _, m in df.iterrows():
            rows.append({
                'title': m.get('title',''), 'first_name': m.get('first_name',''),
                'middle_name': m.get('middle_name',''), 'last_name': m.get('last_name',''),
                'dob_day': m.get('dob_day',''), 'dob_month': m.get('dob_month',''),
                'dob_year': m.get('dob_year',''), 'email': m.get('email',''),
                'phone': m.get('phone',''), 'house': m.get('house',''),
            })
        return _csv_response(rows, f'birthdays_{ts}.csv')

    if kind == 'master_financial':
        rows = []
        for _, r in dues_payments.iterrows():
            rows.append({
                'date': r.get('created_at', ''), 'type': 'Dues',
                'reference': r.get('dues_id', ''),
                'member_name': r.get('member_name', ''),
                'amount': r.get('amount', ''), 'method': r.get('method', ''),
            })
        for _, r in contribs.iterrows():
            rows.append({
                'date': r.get('created_at', ''), 'type': 'Contribution',
                'reference': r.get('campaign_id', ''),
                'member_name': r.get('member_name', ''),
                'amount': r.get('amount', ''), 'method': r.get('method', ''),
            })
        rows.sort(key=lambda x: x['date'])
        return _csv_response(rows, f'master_financial_{ts}.csv')

    if kind == 'executive_summary':
        mc = len(members)
        total_dues = _amt(dues_payments)
        total_contribs = _amt(contribs)
        rows = [
            {'metric': 'Total Members', 'value': mc},
            {'metric': 'Total Dues Collected', 'value': f'GH₵{total_dues:.2f}'},
            {'metric': 'Total Contributions', 'value': f'GH₵{total_contribs:.2f}'},
            {'metric': 'Total Money', 'value': f'GH₵{total_dues + total_contribs:.2f}'},
            {'metric': 'Total Votes', 'value': len(votes)},
            {'metric': 'Total Polls', 'value': len(polls)},
            {'metric': 'Total Campaigns', 'value': len(campaigns)},
            {'metric': 'Generated', 'value': datetime.now().isoformat()},
        ]
        return _csv_response(rows, f'executive_summary_{ts}.csv')

    flash(f'Unknown report: {kind}', 'danger')
    return redirect(url_for('admin.reports'))


# ═══════════════════════════════════════════════════════════
# PDF REPORT ROUTER
# ═══════════════════════════════════════════════════════════
@admin_bp.route('/report-pdf/<kind>')
@_admin_required
def report_pdf(kind):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    members        = _load(T_MEMBERS, MEMBERS_FILE)
    polls          = _load(T_POLLS, POLLS_FILE)
    votes          = _load(T_VOTES, VOTES_FILE)
    contribs       = _load(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE)
    campaigns      = _load(T_CAMPAIGNS, CAMPAIGNS_FILE)
    dues_payments  = _load(T_DUES, DUES_FILE)
    dues_plans     = _load(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE)

    def _amt(df):
        if df.empty or 'amount' not in df.columns:
            return 0.0
        return float(pd.to_numeric(df['amount'], errors='coerce').fillna(0).sum())

    sections = []
    title = 'Report'
    subtitle = ''

    if kind == 'all_members':
        title = 'All Members'
        subtitle = f'{len(members)} registered'
        df = members.copy()
        if 'password_hash' in df.columns:
            df = df.drop(columns=['password_hash'])
        rows = df.to_dict('records') if not df.empty else []
        cols = ['title','first_name','middle_name','last_name','email','phone','house']
        cols = [c for c in cols if c in (rows[0].keys() if rows else [])]
        sections.append(('Members', rows, cols))

    elif kind == 'all_campaigns':
        title = 'Campaigns'
        rows = []
        mc = len(members)
        for _, c in campaigns.iterrows():
            cid = c['campaign_id']
            target = float(c.get('target_amount', 0) or 0)
            sub = contribs[contribs['campaign_id'] == cid] if not contribs.empty else pd.DataFrame()
            raised = _amt(sub)
            rows.append({
                'campaign_id': cid, 'title': c['title'],
                'target': f'{target:.2f}', 'raised': f'{raised:.2f}',
                'funded_pct': round(raised / target * 100, 1) if target else 0,
            })
        sections.append(('Campaigns', rows,
                         ['title','target','raised','funded_pct']))

    elif kind == 'all_dues_plans':
        title = 'Dues Periods'
        rows = []
        mc = len(members)
        for _, d in dues_plans.iterrows():
            did = d['dues_id']
            amount = float(d.get('amount', 0) or 0)
            paid = dues_payments[dues_payments['dues_id'] == did] if not dues_payments.empty else pd.DataFrame()
            collected = _amt(paid)
            rows.append({
                'dues_id': did, 'month': d.get('month', ''), 'year': d.get('year', ''),
                'amount_per_member': f'{amount:.2f}',
                'total_collected': f'{collected:.2f}',
                'collection_pct': round(collected / (amount * mc) * 100, 1) if mc and amount else 0,
            })
        sections.append(('Dues Periods', rows,
                         ['month','year','amount_per_member','total_collected','collection_pct']))

    elif kind == 'poll':
        poll_id = request.args.get('poll_id', '')
        p = polls[polls['poll_id'] == poll_id] if not polls.empty else pd.DataFrame()
        if p.empty:
            flash('Poll not found.', 'danger')
            return redirect(url_for('admin.polls'))
        p = p.iloc[0]
        title = f'Poll: {p["title"]}'
        try:
            opts = json.loads(p.get('options_json', '[]'))
        except Exception:
            opts = []
        pv = votes[votes['poll_id'] == poll_id] if not votes.empty else pd.DataFrame()
        tally = pv['option_id'].value_counts().to_dict() if not pv.empty else {}
        total = len(pv)
        rows = []
        for o in opts:
            c = tally.get(o['id'], 0)
            rows.append({'option_text': o['text'], 'votes': c,
                         'pct': round(c / total * 100, 2) if total else 0})
        sections.append(('Results', rows, ['option_text', 'votes', 'pct']))

    elif kind == 'all_polls':
        title = 'All Polls'
        rows = []
        mc = len(members)
        for _, p in polls.iterrows():
            pid = p['poll_id']
            pv = votes[votes['poll_id'] == pid] if not votes.empty else pd.DataFrame()
            rows.append({
                'poll_id': pid, 'title': p['title'],
                'total_votes': len(pv),
                'turnout_pct': round(len(pv) / mc * 100, 1) if mc else 0,
            })
        sections.append(('Polls', rows,
                         ['poll_id','title','total_votes','turnout_pct']))

    elif kind == 'executive_summary':
        title = 'Executive Summary'
        mc = len(members)
        total_dues = _amt(dues_payments)
        total_contribs = _amt(contribs)
        rows = [
            {'metric': 'Total Members', 'value': mc},
            {'metric': 'Total Dues Collected', 'value': f'GH₵{total_dues:.2f}'},
            {'metric': 'Total Contributions', 'value': f'GH₵{total_contribs:.2f}'},
            {'metric': 'Total Money Collected', 'value': f'GH₵{total_dues + total_contribs:.2f}'},
            {'metric': 'Total Votes Cast', 'value': len(votes)},
            {'metric': 'Total Polls', 'value': len(polls)},
            {'metric': 'Total Campaigns', 'value': len(campaigns)},
        ]
        sections.append(('Summary', rows, ['metric','value']))

    else:
        flash(f'PDF not available for {kind}', 'warning')
        return redirect(url_for('admin.reports'))

    pdf_bytes = build_pdf(title, subtitle, sections)
    return send_file(io.BytesIO(pdf_bytes),
                     mimetype='application/pdf',
                     as_attachment=True,
                     download_name=f'odadea07_{kind}_{ts}.pdf')


# ═══════════════════════════════════════════════════════════
# FULL BACKUP
# ═══════════════════════════════════════════════════════════
@admin_bp.route('/backup')
@_admin_required
def backup():
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    buf = BytesIO()
    tables = [
        (T_MEMBERS, MEMBERS_FILE),
        (T_POLLS, POLLS_FILE),
        (T_VOTES, VOTES_FILE),
        (T_CONTRIBUTIONS, CONTRIBUTIONS_FILE),
        (T_CAMPAIGNS, CAMPAIGNS_FILE),
        (T_DUES, DUES_FILE),
        (T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE),
    ]
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for table, path in tables:
            df = _load(table, path)
            if df.empty:
                continue
            zf.writestr(f'{table}_{ts}.csv', df.to_csv(index=False))
    buf.seek(0)
    return send_file(buf, mimetype='application/zip',
                     as_attachment=True,
                     download_name=f'odadea07_backup_{ts}.zip')


@admin_bp.route('/download/<kind>')
@_admin_required
def download(kind):
    mapping = {
        'members': 'all_members', 'contributions': 'all_contributions',
        'dues': 'all_dues', 'votes': 'all_votes', 'polls': 'all_polls',
        'campaigns': 'all_campaigns', 'dues_plans': 'all_dues_plans',
    }
    nk = mapping.get(kind)
    if not nk:
        flash(f'Unknown report: {kind}', 'danger')
        return redirect(url_for('admin.reports'))
    return redirect(url_for('admin.report', kind=nk))