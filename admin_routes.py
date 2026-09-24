"""
admin_routes.py — ODADEAƐ07 Admin Panel (Supabase-aware, 22 reports)

Data source:
  • SUPABASE_URL + SUPABASE_KEY set → reads from Supabase
  • Otherwise → reads from local CSV files

Reports (all downloadable as CSV):
  POLLS/VOTES
    1. all_polls         — every poll with totals
    2. poll              — specific poll details (?poll_id=...)
    3. all_votes         — every vote ever cast
    4. poll_votes        — votes for a specific poll
    5. turnout           — participation per poll
  DUES
    6. all_dues_plans    — every dues period
    7. dues_plan         — specific period (?dues_id=...)
    8. all_dues          — every dues payment
    9. dues_month        — payments for a month (?month=&year=)
   10. outstanding_dues  — who hasn't paid (all open periods)
   11. top_dues_payers   — ranked by total paid
  CONTRIBUTIONS
   12. all_campaigns     — every campaign
   13. campaign          — specific campaign (?campaign_id=...)
   14. all_contributions — every contribution
   15. campaign_payments — payments for one campaign
   16. outstanding_contribs — who hasn't given to active campaigns
   17. top_contributors  — ranked by total given
  MEMBERSHIP
   18. all_members       — full directory
   19. members_by_house  — grouped by house
   20. members_by_year   — grouped by registration month
   21. inactive_members  — registered but never participated
   22. contact_directory — names + emails + phones only
  COMBINED
   23. master_financial  — every money movement
   24. executive_summary — one-page overview
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

import supabase_client as sb

# ─────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────
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

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'CHANGE-ME-NOW')

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ─────────────────────────────────────────────────────────
# TABLE NAMES
# ─────────────────────────────────────────────────────────
T_MEMBERS        = 'members'
T_POLLS          = 'polls'
T_VOTES          = 'votes'
T_CONTRIBUTIONS  = 'contributions'
T_CAMPAIGNS      = 'contributions_campaigns'
T_DUES           = 'dues'
T_DUES_CAMPAIGNS = 'dues_campaigns'


# ─────────────────────────────────────────────────────────
# RATE LIMITER (admin login)
# ─────────────────────────────────────────────────────────
_admin_attempts = defaultdict(list)
_WINDOW = timedelta(minutes=15)
_MAX = 5


def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _locked(ip):
    now = datetime.now()
    _admin_attempts[ip] = [t for t in _admin_attempts[ip] if now - t < _WINDOW]
    return len(_admin_attempts[ip]) >= _MAX


def _fail(ip):
    _admin_attempts[ip].append(datetime.now())


def _clear(ip):
    _admin_attempts.pop(ip, None)


# ─────────────────────────────────────────────────────────
# DATA HELPERS
# ─────────────────────────────────────────────────────────
def _load_csv(path):
    if os.path.exists(path):
        return pd.read_csv(path, dtype=str).fillna('')
    return pd.DataFrame()


def _save_csv(path, df):
    df.to_csv(path, index=False)


def _load(table_name, csv_path):
    """Supabase-or-CSV loader → always DataFrame of strings."""
    if sb.SUPABASE_ENABLED:
        rows = sb.fetch_all(table_name)
        if rows:
            return pd.DataFrame(rows).fillna('').astype(str)
        return pd.DataFrame()
    return _load_csv(csv_path)


def _insert(table_name, csv_path, row):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(table_name).insert(row).execute()
                return True
            except Exception as e:
                print(f'[Supabase insert failed for {table_name}]: {e}')
    df = _load_csv(csv_path)
    new = pd.DataFrame([row])
    out = pd.concat([df, new], ignore_index=True) if not df.empty else new
    _save_csv(csv_path, out)
    return True


def _delete_where(table_name, csv_path, col, val):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(table_name).delete().eq(col, val).execute()
                return True
            except Exception as e:
                print(f'[Supabase delete failed]: {e}')
                return False
    df = _load_csv(csv_path)
    if df.empty or col not in df.columns:
        return False
    before = len(df)
    df = df[df[col].astype(str) != str(val)]
    if len(df) == before:
        return False
    _save_csv(csv_path, df)
    return True


def _update_where(table_name, csv_path, id_col, id_val, updates):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(table_name).update(updates).eq(id_col, id_val).execute()
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


def _csv_response(rows, filename):
    """Build a CSV response from a list of dicts."""
    buf = io.StringIO()
    if rows:
        # Union of all keys across rows (handles ragged dicts)
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


def _admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get('is_admin'):
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
</head>
<body>
<header class="main-header">
    <div class="header-content">
        <a href="{{ url_for('admin.home') }}" class="logo-section">
            <img src="{{ url_for('static', filename='images/presec-badge.png') }}"
                 class="school-badge" onerror="this.style.display='none'">
            <div class="logo-text">
                <h1>ODADEAƐ07 <span style="color:#f5c518;font-size:0.7em;">ADMIN</span></h1>
                <p>Presbyterian Boys' Secondary School • 2007</p>
            </div>
        </a>
        <nav class="main-nav">
            {% if session.is_admin %}
                <a href="{{ url_for('admin.home') }}">📊 Dashboard</a>
                <a href="{{ url_for('admin.polls') }}">🗳️ Polls</a>
                <a href="{{ url_for('admin.contrib') }}">🎯 Contributions</a>
                <a href="{{ url_for('admin.dues') }}">📅 Dues</a>
                <a href="{{ url_for('admin.members') }}">👥 Members</a>
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
        <p><strong>ODADEAƐ07 Admin Panel</strong> — internal use only</p>
        <p class="motto">"In Lumine Tuo Videbimus Lumen"</p>
        <p style="opacity:0.7;font-size:0.8em;">
          Data source: {{ 'Supabase' if supabase_on else 'Local CSV' }}
        </p>
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
        supabase_on=sb.SUPABASE_ENABLED,
    )


# ─────────────────────────────────────────────────────────
# LOGIN / LOGOUT
# ─────────────────────────────────────────────────────────
@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    ip = _client_ip()
    if request.method == 'POST':
        if _locked(ip):
            flash('Too many failed attempts. Try again in 15 minutes.', 'danger')
            return redirect(url_for('admin.login'))

        if request.form.get('password') == ADMIN_PASSWORD:
            _clear(ip)
            session['is_admin'] = True
            session.permanent = True
            flash('Welcome, admin.', 'success')
            return redirect(url_for('admin.home'))

        _fail(ip)
        remaining = _MAX - len(_admin_attempts[ip])
        flash(f'Wrong password. {remaining} attempts left.' if remaining > 0
              else 'Too many failed attempts. Locked for 15 minutes.', 'danger')

    body = render_template_string("""
    <div class="form-container">
      <h1>🛡️ Admin Login</h1>
      <p class="form-subtitle">Private access — ODADEAƐ07</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group">
          <label>Admin Password</label>
          <input type="password" name="password" required autofocus>
        </div>
        <button class="btn btn-primary btn-full">🔓 Enter</button>
      </form>
      <p class="form-footer"><a href="{{ url_for('index') }}">← Back to site</a></p>
    </div>
    """)
    return _page(body)


@admin_bp.route('/logout')
def logout():
    session.pop('is_admin', None)
    flash('Admin logged out.', 'info')
    return redirect(url_for('admin.login'))


# ─────────────────────────────────────────────────────────
# DASHBOARD
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
    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🛡️ Admin Dashboard</h1>
      <p class="subtitle">Full control • live data</p></div>
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
        <div class="stat-sub">{{ s.votes }} votes cast</div></div>
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

    <div class="admin-actions">
      <a href="{{ url_for('admin.polls') }}"   class="btn btn-primary">🗳️ Manage Polls</a>
      <a href="{{ url_for('admin.contrib') }}" class="btn btn-primary">🎯 Manage Contributions</a>
      <a href="{{ url_for('admin.dues') }}"    class="btn btn-primary">📅 Manage Dues</a>
      <a href="{{ url_for('admin.members') }}" class="btn btn-primary">👥 Manage Members</a>
      <a href="{{ url_for('admin.reports') }}" class="btn btn-secondary">📈 Reports & Downloads</a>
      <a href="{{ url_for('admin.backup') }}"  class="btn btn-secondary">💾 Download Full Backup (ZIP)</a>
    </div>
    """, s=stats)
    return _page(body)


# ─────────────────────────────────────────────────────────
# POLLS (manage)
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
            except ValueError:
                n = 2
            opts = [_sanitize(request.form.get(f'option_{i}', ''), 120) for i in range(n)]
            opts = [o for o in opts if o]
            if title and len(opts) >= 2:
                _insert(T_POLLS, POLLS_FILE, {
                    'poll_id': f"POLL{int(time.time())}_{random.randint(100,999)}",
                    'title': title, 'description': desc,
                    'options_json': json.dumps([{'id': f'opt_{i}', 'text': t}
                                                for i, t in enumerate(opts)]),
                    'created_at': datetime.now().isoformat(),
                    'active': 'True',
                })
                flash(f'✅ Poll created: "{title}"', 'success')
            else:
                flash('Need a title and at least 2 options.', 'danger')

        elif action == 'delete':
            pid = request.form.get('poll_id')
            if pid and _delete_where(T_POLLS, POLLS_FILE, 'poll_id', pid):
                _delete_where(T_VOTES, VOTES_FILE, 'poll_id', pid)
                flash('Poll and its votes deleted.', 'success')
            else:
                flash('Poll not found.', 'danger')

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

    reports = []
    if not polls_df.empty:
        for _, p in polls_df.iterrows():
            pid = p['poll_id']
            try:
                opts = json.loads(p.get('options_json', '[]'))
            except Exception:
                opts = []
            pv = votes_df[votes_df['poll_id'] == pid] if not votes_df.empty else pd.DataFrame()
            tally = pv['option_id'].value_counts().to_dict() if not pv.empty else {}
            total = len(pv)
            results = []
            for o in opts:
                c = tally.get(o['id'], 0)
                results.append({
                    'text': o['text'], 'votes': c,
                    'pct': round(c / total * 100, 1) if total else 0,
                })
            winner = max(results, key=lambda x: x['votes'])['text'] if results and total else None
            reports.append({
                'id': pid, 'title': p['title'],
                'description': p.get('description', ''),
                'active': str(p.get('active', True)).lower() in ['true', '1', 'yes'],
                'created_at': str(p.get('created_at', ''))[:10],
                'total': total,
                'turnout': round(total / member_count * 100, 1) if member_count else 0,
                'results': results, 'winner': winner,
                'voters': pv[['member_name', 'voted_at']].to_dict('records') if not pv.empty else [],
            })

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🗳️ Polls</h1><p class="subtitle">{{ reports|length }} poll(s)</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.report', kind='all_polls') }}" class="btn btn-secondary">⬇ All Polls</a>
        <a href="{{ url_for('admin.report', kind='all_votes') }}" class="btn btn-secondary">⬇ All Votes</a>
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container">
      <h1>➕ Create a Poll</h1>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="create">
        <div class="form-group"><label>Title *</label>
          <input name="title" required maxlength="200"></div>
        <div class="form-group"><label>Description (optional)</label>
          <textarea name="description" maxlength="400"></textarea></div>
        <div class="form-group"><label>Option 1 *</label>
          <input name="option_0" required maxlength="120"></div>
        <div class="form-group"><label>Option 2 *</label>
          <input name="option_1" required maxlength="120"></div>
        <div class="form-group"><label>Option 3 (optional)</label>
          <input name="option_2" maxlength="120"></div>
        <div class="form-group"><label>Option 4 (optional)</label>
          <input name="option_3" maxlength="120"></div>
        <input type="hidden" name="option_count" value="4">
        <button class="btn btn-primary btn-full">Create Poll</button>
      </form>
    </div>

    {% for p in reports %}
    <div class="poll-report-card">
      <div class="poll-report-header">
        <div>
          <h2>{{ p.title }}
            <span class="status-badge status-{{ 'active' if p.active else 'closed' }}">
              {{ 'Active' if p.active else 'Closed' }}</span></h2>
          <p>{{ p.description }}</p>
          <p class="poll-meta">Created {{ p.created_at }} • ID <code>{{ p.id }}</code></p>
        </div>
        <div class="poll-totals">
          <div class="poll-total-value">{{ p.total }}</div>
          <div class="poll-total-label">Votes</div>
          <div class="poll-turnout">{{ p.turnout }}% turnout</div>
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

      {% if p.voters %}
      <details class="voters-details">
        <summary>View {{ p.voters|length }} voter(s)</summary>
        <div class="table-wrapper" style="margin-top:1rem;">
          <table class="report-table">
            <thead><tr><th>Member</th><th>Voted At</th></tr></thead>
            <tbody>
              {% for v in p.voters %}
              <tr><td>{{ v.member_name }}</td><td>{{ v.voted_at[:19] }}</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </details>
      {% endif %}

      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:1rem;padding-top:1rem;border-top:1px dashed var(--gray-200);">
        <a href="{{ url_for('admin.report', kind='poll', poll_id=p.id) }}" class="btn btn-small btn-primary">⬇ Poll Report</a>
        <a href="{{ url_for('admin.report', kind='poll_votes', poll_id=p.id) }}" class="btn btn-small btn-secondary">⬇ Votes</a>
        <form method="POST" style="display:inline;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="toggle">
          <input type="hidden" name="poll_id" value="{{ p.id }}">
          <button class="btn btn-small btn-secondary">
            {{ '🔒 Close' if p.active else '🔓 Re-open' }}
          </button>
        </form>
        <form method="POST" style="display:inline;"
              onsubmit="return confirm('Delete this poll and all votes?');">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="poll_id" value="{{ p.id }}">
          <button class="btn btn-small btn-primary">🗑️ Delete</button>
        </form>
      </div>
    </div>
    {% else %}
    <p class="empty-state">No polls yet. Create one above.</p>
    {% endfor %}
    """, reports=reports)
    return _page(body)


# ─────────────────────────────────────────────────────────
# CONTRIBUTIONS (manage)
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
                flash(f'✅ Campaign created: "{title}"', 'success')
            else:
                flash('Title and target amount required.', 'danger')

        elif action == 'delete':
            cid = request.form.get('campaign_id')
            if cid and _delete_where(T_CAMPAIGNS, CAMPAIGNS_FILE, 'campaign_id', cid):
                _delete_where(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE, 'campaign_id', cid)
                flash('Campaign and its payments deleted.', 'success')
            else:
                flash('Campaign not found.', 'danger')

        elif action == 'toggle':
            cid = request.form.get('campaign_id')
            df = _load(T_CAMPAIGNS, CAMPAIGNS_FILE)
            if cid and not df.empty:
                row = df[df['campaign_id'] == cid]
                if not row.empty:
                    cur = str(row.iloc[0]['active']).lower() in ['true', '1', 'yes']
                    _update_where(T_CAMPAIGNS, CAMPAIGNS_FILE, 'campaign_id', cid,
                                  {'active': str(not cur)})
                    flash(f'Campaign {"closed" if cur else "re-opened"}.', 'success')

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
                'members': member_count,
                'active': str(c.get('active', True)).lower() in ['true', '1', 'yes'],
                'payments': sub.to_dict('records') if not sub.empty else [],
            })

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🎯 Contribution Campaigns</h1>
      <p class="subtitle">{{ reports|length }} campaign(s)</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.report', kind='all_campaigns') }}" class="btn btn-secondary">⬇ All Campaigns</a>
        <a href="{{ url_for('admin.report', kind='all_contributions') }}" class="btn btn-secondary">⬇ All Contributions</a>
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
        <div class="form-group"><label>Description (optional)</label>
          <textarea name="description" maxlength="400"></textarea></div>
        <div class="form-group"><label>Target amount (GH₵) *</label>
          <input type="number" step="0.01" name="target_amount" required></div>
        <button class="btn btn-primary btn-full">Create Campaign</button>
      </form>
    </div>

    {% for c in reports %}
    <div class="poll-report-card">
      <div class="poll-report-header">
        <div>
          <h2>{{ c.title }}
            <span class="status-badge status-{{ 'active' if c.active else 'closed' }}">
              {{ 'Active' if c.active else 'Closed' }}</span></h2>
          <p>{{ c.description }}</p>
        </div>
        <div class="poll-totals">
          <div class="poll-total-value">GH₵{{ "%.2f"|format(c.raised) }}</div>
          <div class="poll-total-label">of GH₵{{ "%.2f"|format(c.target) }}</div>
          <div class="poll-turnout">{{ c.raw_pct }}% funded</div>
        </div>
      </div>
      <div class="progress-track">
        <div class="progress-fill {% if c.pct >= 100 %}full{% endif %}" style="width: {{ c.pct }}%"></div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:0.75rem;margin:1rem 0;">
        <div><strong>{{ c.paid }}</strong> paid</div>
        <div><strong>{{ c.unpaid }}</strong> unpaid</div>
        <div><strong>{{ c.members }}</strong> members</div>
        <div><strong>GH₵{{ "%.2f"|format(c.target - c.raised if c.raised < c.target else 0) }}</strong> remaining</div>
      </div>

      {% if c.payments %}
      <details class="voters-details">
        <summary>View {{ c.payments|length }} payment(s)</summary>
        <div class="table-wrapper" style="margin-top:1rem;">
          <table class="report-table">
            <thead><tr><th>Date</th><th>Member</th><th>Amount</th><th>Method</th></tr></thead>
            <tbody>
              {% for p in c.payments %}
              <tr><td>{{ p.created_at[:10] }}</td><td>{{ p.member_name }}</td>
                  <td class="amount">GH₵{{ "%.2f"|format(p.amount|float) }}</td>
                  <td>{{ p.method }}</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </details>
      {% endif %}

      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:1rem;padding-top:1rem;border-top:1px dashed var(--gray-200);">
        <a href="{{ url_for('admin.report', kind='campaign', campaign_id=c.id) }}" class="btn btn-small btn-primary">⬇ Campaign Report</a>
        <a href="{{ url_for('admin.report', kind='campaign_payments', campaign_id=c.id) }}" class="btn btn-small btn-secondary">⬇ Payments</a>
        <form method="POST" style="display:inline;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="toggle">
          <input type="hidden" name="campaign_id" value="{{ c.id }}">
          <button class="btn btn-small btn-secondary">
            {{ '🔒 Close' if c.active else '🔓 Re-open' }}
          </button>
        </form>
        <form method="POST" style="display:inline;"
              onsubmit="return confirm('Delete this campaign and all payments?');">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="campaign_id" value="{{ c.id }}">
          <button class="btn btn-small btn-primary">🗑️ Delete</button>
        </form>
      </div>
    </div>
    {% else %}
    <p class="empty-state">No campaigns yet. Create one above.</p>
    {% endfor %}
    """, reports=reports)
    return _page(body)


# ─────────────────────────────────────────────────────────
# DUES (manage)
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
                flash(f'✅ Dues created: {month} {year} — GH₵{amount:.2f}', 'success')
            else:
                flash('Month, year and amount required.', 'danger')

        elif action == 'delete':
            did = request.form.get('dues_id')
            if did and _delete_where(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE, 'dues_id', did):
                _delete_where(T_DUES, DUES_FILE, 'dues_id', did)
                flash('Dues period and payments deleted.', 'success')
            else:
                flash('Dues period not found.', 'danger')

        elif action == 'toggle':
            did = request.form.get('dues_id')
            df = _load(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE)
            if did and not df.empty:
                row = df[df['dues_id'] == did]
                if not row.empty:
                    cur = str(row.iloc[0]['active']).lower() in ['true', '1', 'yes']
                    _update_where(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE, 'dues_id', did,
                                  {'active': str(not cur)})
                    flash(f'Dues {"closed" if cur else "re-opened"}.', 'success')

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
                'members': member_count,
                'active': str(d.get('active', True)).lower() in ['true', '1', 'yes'],
                'payments': sub.to_dict('records') if not sub.empty else [],
            })

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>📅 Monthly Dues</h1><p class="subtitle">{{ reports|length }} period(s)</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.report', kind='all_dues_plans') }}" class="btn btn-secondary">⬇ All Plans</a>
        <a href="{{ url_for('admin.report', kind='all_dues') }}" class="btn btn-secondary">⬇ All Payments</a>
        <a href="{{ url_for('admin.report', kind='outstanding_dues') }}" class="btn btn-secondary">⬇ Outstanding</a>
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
            <input name="month" required placeholder="October" maxlength="30"></div>
          <div class="form-group"><label>Year *</label>
            <input name="year" required placeholder="2026" maxlength="10"></div>
        </div>
        <div class="form-group"><label>Amount per member (GH₵) *</label>
          <input type="number" step="0.01" name="amount" required></div>
        <button class="btn btn-primary btn-full">Create Dues</button>
      </form>
    </div>

    {% for d in reports %}
    <div class="poll-report-card">
      <div class="poll-report-header">
        <div>
          <h2>{{ d.month }} {{ d.year }}
            <span class="status-badge status-{{ 'active' if d.active else 'closed' }}">
              {{ 'Open' if d.active else 'Closed' }}</span></h2>
          <p>GH₵{{ "%.2f"|format(d.amount) }} per member</p>
        </div>
        <div class="poll-totals">
          <div class="poll-total-value">GH₵{{ "%.2f"|format(d.collected) }}</div>
          <div class="poll-total-label">of GH₵{{ "%.2f"|format(d.expected) }}</div>
          <div class="poll-turnout">{{ d.raw_pct }}% collected</div>
        </div>
      </div>
      <div class="progress-track">
        <div class="progress-fill {% if d.pct >= 100 %}full{% endif %}" style="width: {{ d.pct }}%"></div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:0.75rem;margin:1rem 0;">
        <div><strong>{{ d.paid }}</strong> paid</div>
        <div><strong>{{ d.unpaid }}</strong> unpaid</div>
        <div><strong>{{ d.members }}</strong> members</div>
        <div><strong>GH₵{{ "%.2f"|format(d.expected - d.collected if d.collected < d.expected else 0) }}</strong> remaining</div>
      </div>

      {% if d.payments %}
      <details class="voters-details">
        <summary>View {{ d.payments|length }} payment(s)</summary>
        <div class="table-wrapper" style="margin-top:1rem;">
          <table class="report-table">
            <thead><tr><th>Date</th><th>Member</th><th>Amount</th><th>Method</th></tr></thead>
            <tbody>
              {% for p in d.payments %}
              <tr><td>{{ p.created_at[:10] }}</td><td>{{ p.member_name }}</td>
                  <td class="amount">GH₵{{ "%.2f"|format(p.amount|float) }}</td>
                  <td>{{ p.method }}</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </details>
      {% endif %}

      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:1rem;padding-top:1rem;border-top:1px dashed var(--gray-200);">
        <a href="{{ url_for('admin.report', kind='dues_plan', dues_id=d.id) }}" class="btn btn-small btn-primary">⬇ Plan Report</a>
        <a href="{{ url_for('admin.report', kind='dues_month', month=d.month, year=d.year) }}" class="btn btn-small btn-secondary">⬇ Month Report</a>
        <form method="POST" style="display:inline;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="toggle">
          <input type="hidden" name="dues_id" value="{{ d.id }}">
          <button class="btn btn-small btn-secondary">
            {{ '🔒 Close' if d.active else '🔓 Re-open' }}
          </button>
        </form>
        <form method="POST" style="display:inline;"
              onsubmit="return confirm('Delete this dues period and all payments?');">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="dues_id" value="{{ d.id }}">
          <button class="btn btn-small btn-primary">🗑️ Delete</button>
        </form>
      </div>
    </div>
    {% else %}
    <p class="empty-state">No dues periods yet. Create one above.</p>
    {% endfor %}
    """, reports=reports)
    return _page(body)


# ─────────────────────────────────────────────────────────
# MEMBERS (manage)
# ─────────────────────────────────────────────────────────
@admin_bp.route('/members', methods=['GET', 'POST'])
@_admin_required
def members():
    if request.method == 'POST':
        action = request.form.get('action', 'add')

        if action == 'add':
            full_name = _sanitize(request.form.get('full_name', ''), 120)
            email     = _sanitize(request.form.get('email', ''), 120).lower()
            phone     = _sanitize(request.form.get('phone', ''), 40)
            house     = _sanitize(request.form.get('house', ''), 60)
            if full_name and email:
                from werkzeug.security import generate_password_hash
                _insert(T_MEMBERS, MEMBERS_FILE, {
                    'member_id': f"MEM{int(time.time())}{random.randint(100,999)}",
                    'full_name': full_name, 'email': email,
                    'phone': phone, 'house': house,
                    'password_hash': generate_password_hash('changeme123'),
                    'registered_at': datetime.now().isoformat(),
                })
                flash(f'✅ Member added: {full_name} (default password: changeme123)', 'success')
            else:
                flash('Name and email required.', 'danger')

        elif action == 'edit':
            mid = request.form.get('member_id')
            updates = {
                'full_name': _sanitize(request.form.get('full_name', ''), 120),
                'email':     _sanitize(request.form.get('email', ''), 120).lower(),
                'phone':     _sanitize(request.form.get('phone', ''), 40),
                'house':     _sanitize(request.form.get('house', ''), 60),
            }
            if mid and _update_where(T_MEMBERS, MEMBERS_FILE, 'member_id', mid, updates):
                flash('Member updated.', 'success')
            else:
                flash('Member not found.', 'danger')

        elif action == 'delete':
            mid = request.form.get('member_id')
            if mid and _delete_where(T_MEMBERS, MEMBERS_FILE, 'member_id', mid):
                flash('Member deleted.', 'success')
            else:
                flash('Member not found.', 'danger')

        return redirect(url_for('admin.members'))

    df = _load(T_MEMBERS, MEMBERS_FILE)
    rows = df.to_dict('records') if not df.empty else []
    for r in rows:
        r.pop('password_hash', None)

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>👥 Members ({{ rows|length }})</h1></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.report', kind='all_members') }}" class="btn btn-secondary">⬇ All Members</a>
        <a href="{{ url_for('admin.report', kind='members_by_house') }}" class="btn btn-secondary">⬇ By House</a>
        <a href="{{ url_for('admin.report', kind='contact_directory') }}" class="btn btn-secondary">⬇ Contacts</a>
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container">
      <h1>➕ Add Member</h1>
      <p class="form-subtitle">Default password: changeme123</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="add">
        <div class="form-row">
          <div class="form-group"><label>Full Name *</label>
            <input name="full_name" required maxlength="120"></div>
          <div class="form-group"><label>Email *</label>
            <input type="email" name="email" required maxlength="120"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Phone</label>
            <input name="phone" maxlength="40"></div>
          <div class="form-group"><label>House</label>
            <input name="house" maxlength="60"></div>
        </div>
        <button class="btn btn-primary btn-full">Add Member</button>
      </form>
    </div>

    <div class="table-wrapper">
      <table class="report-table full-width">
        <thead><tr>
          <th>Name</th><th>Email</th><th>Phone</th><th>House</th><th>Actions</th>
        </tr></thead>
        <tbody>
        {% for m in rows %}
          <tr>
            <td><strong>{{ m.get('full_name','') }}</strong></td>
            <td>{{ m.get('email','') }}</td>
            <td>{{ m.get('phone','') or '—' }}</td>
            <td>{{ m.get('house','') or '—' }}</td>
            <td>
              <details>
                <summary style="cursor:pointer;color:var(--presec-blue);font-weight:700;">Edit</summary>
                <form method="POST" style="margin-top:0.5rem;">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                  <input type="hidden" name="action" value="edit">
                  <input type="hidden" name="member_id" value="{{ m.member_id }}">
                  <div class="form-group"><label>Name</label>
                    <input name="full_name" value="{{ m.full_name }}" maxlength="120"></div>
                  <div class="form-group"><label>Email</label>
                    <input name="email" value="{{ m.email }}" maxlength="120"></div>
                  <div class="form-group"><label>Phone</label>
                    <input name="phone" value="{{ m.phone }}" maxlength="40"></div>
                  <div class="form-group"><label>House</label>
                    <input name="house" value="{{ m.house }}" maxlength="60"></div>
                  <button class="btn btn-small btn-primary">Save</button>
                </form>
                <form method="POST" style="margin-top:0.5rem;"
                      onsubmit="return confirm('Delete this member?');">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                  <input type="hidden" name="action" value="delete">
                  <input type="hidden" name="member_id" value="{{ m.member_id }}">
                  <button class="btn btn-small btn-primary">🗑️ Delete</button>
                </form>
              </details>
            </td>
          </tr>
        {% else %}
          <tr><td colspan="5" class="empty-state">No members yet.</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    """, rows=rows)
    return _page(body)


# ═══════════════════════════════════════════════════════════
# REPORTS HUB
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
      <div><h1>📈 Reports & Downloads</h1>
      <p class="subtitle">24 reports • all downloadable as CSV</p></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.backup') }}" class="btn btn-primary">💾 Full Backup (ZIP)</a>
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
        <div class="stat-title">Dues Collected</div></div>
      <div class="report-stat-card"><div class="stat-icon">🗳️</div>
        <div class="stat-value">{{ votes_count }}</div>
        <div class="stat-title">Votes Cast</div>
        <div class="stat-sub">{{ polls_count }} polls</div></div>
    </div>

    <!-- ══════ VOTING ══════ -->
    <div class="report-section">
      <h2>🗳️ Voting Reports</h2>
      <div class="report-cards-grid">
        <div class="report-card">
          <h3>All Polls</h3>
          <p>Every poll with totals and winner.</p>
          <a href="{{ url_for('admin.report', kind='all_polls') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>All Votes</h3>
          <p>Every vote ever cast (raw data).</p>
          <a href="{{ url_for('admin.report', kind='all_votes') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Turnout by Poll</h3>
          <p>Participation per poll.</p>
          <a href="{{ url_for('admin.report', kind='turnout') }}" class="btn btn-primary">⬇ Download</a>
        </div>
      </div>
      <div class="form-container" style="max-width:520px;margin-top:1rem;">
        <h3>Specific Poll Report</h3>
        <form method="GET" action="{{ url_for('admin.report', kind='poll') }}">
          <div class="form-group"><label>Poll ID</label>
            <input name="poll_id" placeholder="POLL1234..." required></div>
          <button class="btn btn-primary">⬇ Download</button>
        </form>
      </div>
    </div>

    <!-- ══════ DUES ══════ -->
    <div class="report-section">
      <h2>📅 Dues Reports</h2>
      <div class="report-cards-grid">
        <div class="report-card">
          <h3>All Dues Periods</h3>
          <p>Every month configured.</p>
          <a href="{{ url_for('admin.report', kind='all_dues_plans') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>All Dues Payments</h3>
          <p>Every payment ever recorded.</p>
          <a href="{{ url_for('admin.report', kind='all_dues') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Outstanding Dues</h3>
          <p>Who still owes money.</p>
          <a href="{{ url_for('admin.report', kind='outstanding_dues') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Top Dues Payers</h3>
          <p>Ranked by total paid.</p>
          <a href="{{ url_for('admin.report', kind='top_dues_payers') }}" class="btn btn-primary">⬇ Download</a>
        </div>
      </div>
      <div class="form-container" style="max-width:520px;margin-top:1rem;">
        <h3>Specific Month Report</h3>
        <form method="GET" action="{{ url_for('admin.report', kind='dues_month') }}">
          <div class="form-row">
            <div class="form-group"><label>Month</label>
              <input name="month" placeholder="October" required></div>
            <div class="form-group"><label>Year</label>
              <input name="year" placeholder="2026" required></div>
          </div>
          <button class="btn btn-primary">⬇ Download</button>
        </form>
      </div>
    </div>

    <!-- ══════ CONTRIBUTIONS ══════ -->
    <div class="report-section">
      <h2>🎯 Contribution Reports</h2>
      <div class="report-cards-grid">
        <div class="report-card">
          <h3>All Campaigns</h3>
          <p>Every campaign with progress.</p>
          <a href="{{ url_for('admin.report', kind='all_campaigns') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>All Contributions</h3>
          <p>Every contribution ever made.</p>
          <a href="{{ url_for('admin.report', kind='all_contributions') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Outstanding Contributions</h3>
          <p>Who hasn't given yet.</p>
          <a href="{{ url_for('admin.report', kind='outstanding_contribs') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Top Contributors</h3>
          <p>Ranked by total given.</p>
          <a href="{{ url_for('admin.report', kind='top_contributors') }}" class="btn btn-primary">⬇ Download</a>
        </div>
      </div>
      <div class="form-container" style="max-width:520px;margin-top:1rem;">
        <h3>Specific Campaign Report</h3>
        <form method="GET" action="{{ url_for('admin.report', kind='campaign') }}">
          <div class="form-group"><label>Campaign ID</label>
            <input name="campaign_id" placeholder="CAMP1234..." required></div>
          <button class="btn btn-primary">⬇ Download</button>
        </form>
      </div>
    </div>

    <!-- ══════ MEMBERSHIP ══════ -->
    <div class="report-section">
      <h2>👥 Membership Reports</h2>
      <div class="report-cards-grid">
        <div class="report-card">
          <h3>All Members</h3>
          <p>Full directory.</p>
          <a href="{{ url_for('admin.report', kind='all_members') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>By House</h3>
          <p>Grouped by house.</p>
          <a href="{{ url_for('admin.report', kind='members_by_house') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>By Registration Month</h3>
          <p>Growth over time.</p>
          <a href="{{ url_for('admin.report', kind='members_by_year') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Inactive Members</h3>
          <p>Registered but never participated.</p>
          <a href="{{ url_for('admin.report', kind='inactive_members') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Contact Directory</h3>
          <p>Names, emails, phones only.</p>
          <a href="{{ url_for('admin.report', kind='contact_directory') }}" class="btn btn-primary">⬇ Download</a>
        </div>
      </div>
    </div>

    <!-- ══════ COMBINED ══════ -->
    <div class="report-section">
      <h2>📊 Combined Reports</h2>
      <div class="report-cards-grid">
        <div class="report-card">
          <h3>Master Financial</h3>
          <p>Every money movement in one file.</p>
          <a href="{{ url_for('admin.report', kind='master_financial') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Executive Summary</h3>
          <p>One-page overview for the committee.</p>
          <a href="{{ url_for('admin.report', kind='executive_summary') }}" class="btn btn-primary">⬇ Download</a>
        </div>
        <div class="report-card">
          <h3>Full Backup (ZIP)</h3>
          <p>All tables in a single ZIP.</p>
          <a href="{{ url_for('admin.backup') }}" class="btn btn-primary">⬇ Download</a>
        </div>
      </div>
    </div>
    """,
    member_count=len(members), contrib_total=_sum(contrib),
    dues_total=_sum(dues), votes_count=len(votes), polls_count=len(polls))
    return _page(body)


# ═══════════════════════════════════════════════════════════
# REPORT DOWNLOAD ROUTER — all 24 reports
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

    # ── helpers ──
    def _amt(df, col='amount'):
        if df.empty or col not in df.columns:
            return 0.0
        return float(pd.to_numeric(df[col], errors='coerce').fillna(0).sum())

    def _records(df):
        return df.to_dict('records') if not df.empty else []

    # ═══════════════════════════════════════════════════
    # POLLS / VOTES
    # ═══════════════════════════════════════════════════
    if kind == 'all_polls':
        rows = []
        member_count = len(members)
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
                        winner = o['text']
                        break
            rows.append({
                'poll_id': pid,
                'title': p['title'],
                'description': p.get('description', ''),
                'active': p.get('active', ''),
                'created_at': p.get('created_at', ''),
                'total_votes': len(pv),
                'turnout_pct': round(len(pv) / member_count * 100, 1) if member_count else 0,
                'winner': winner,
            })
        return _csv_response(rows, f'all_polls_{ts}.csv')

    if kind == 'poll':
        poll_id = request.args.get('poll_id', '')
        if not poll_id:
            flash('Missing poll_id.', 'danger')
            return redirect(url_for('admin.reports'))
        p = polls[polls['poll_id'] == poll_id] if not polls.empty else pd.DataFrame()
        if p.empty:
            flash('Poll not found.', 'danger')
            return redirect(url_for('admin.reports'))
        p = p.iloc[0]
        try:
            opts = json.loads(p.get('options_json', '[]'))
        except Exception:
            opts = []
        pv = votes[votes['poll_id'] == poll_id] if not votes.empty else pd.DataFrame()
        tally = pv['option_id'].value_counts().to_dict() if not pv.empty else {}
        total = len(pv)
        member_count = len(members)
        rows = []
        for o in opts:
            c = tally.get(o['id'], 0)
            rows.append({
                'poll_id': poll_id,
                'title': p['title'],
                'option_id': o['id'],
                'option_text': o['text'],
                'votes': c,
                'pct': round(c / total * 100, 2) if total else 0,
                'total_poll_votes': total,
                'turnout_pct': round(total / member_count * 100, 1) if member_count else 0,
            })
        return _csv_response(rows, f'poll_{poll_id}_{ts}.csv')

    if kind == 'all_votes':
        rows = _records(votes)
        # Enrich with poll title and option text
        poll_titles = {r['poll_id']: r['title'] for _, r in polls.iterrows()} if not polls.empty else {}
        option_texts = {}
        for _, p in polls.iterrows():
            try:
                for o in json.loads(p.get('options_json', '[]')):
                    option_texts[(p['poll_id'], o['id'])] = o['text']
            except Exception:
                pass
        for r in rows:
            r['poll_title'] = poll_titles.get(r.get('poll_id', ''), '')
            r['option_text'] = option_texts.get((r.get('poll_id', ''), r.get('option_id', '')), '')
        return _csv_response(rows, f'all_votes_{ts}.csv')

    if kind == 'poll_votes':
        poll_id = request.args.get('poll_id', '')
        pv = votes[votes['poll_id'] == poll_id] if not votes.empty else pd.DataFrame()
        return _csv_response(_records(pv), f'poll_votes_{poll_id}_{ts}.csv')

    if kind == 'turnout':
        member_count = len(members)
        rows = []
        for _, p in polls.iterrows():
            pid = p['poll_id']
            pv = votes[votes['poll_id'] == pid] if not votes.empty else pd.DataFrame()
            voters = set(pv['member_id'].tolist()) if not pv.empty else set()
            non_voters = members[~members['member_id'].isin(voters)]['full_name'].tolist() if not members.empty else []
            rows.append({
                'poll_id': pid,
                'poll_title': p['title'],
                'total_members': member_count,
                'voted': len(voters),
                'did_not_vote': len(non_voters),
                'turnout_pct': round(len(voters) / member_count * 100, 1) if member_count else 0,
                'non_voters': '; '.join(non_voters[:50]),
            })
        return _csv_response(rows, f'turnout_{ts}.csv')

    # ═══════════════════════════════════════════════════
    # DUES
    # ═══════════════════════════════════════════════════
    if kind == 'all_dues_plans':
        member_count = len(members)
        rows = []
        for _, d in dues_plans.iterrows():
            did = d['dues_id']
            amount = float(d.get('amount', 0) or 0)
            paid = dues_payments[dues_payments['dues_id'] == did] if not dues_payments.empty else pd.DataFrame()
            collected = _amt(paid)
            expected = amount * member_count
            paid_ids = set(paid['member_id'].tolist()) if not paid.empty else set()
            rows.append({
                'dues_id': did,
                'month': d.get('month', ''),
                'year': d.get('year', ''),
                'amount_per_member': amount,
                'total_expected': expected,
                'total_collected': collected,
                'outstanding': expected - collected,
                'collection_pct': round(collected / expected * 100, 1) if expected else 0,
                'paid_count': len(paid_ids),
                'unpaid_count': member_count - len(paid_ids),
                'total_members': member_count,
                'active': d.get('active', ''),
                'created_at': d.get('created_at', ''),
            })
        return _csv_response(rows, f'all_dues_plans_{ts}.csv')

    if kind == 'dues_plan':
        dues_id = request.args.get('dues_id', '')
        d = dues_plans[dues_plans['dues_id'] == dues_id] if not dues_plans.empty else pd.DataFrame()
        if d.empty:
            flash('Dues period not found.', 'danger')
            return redirect(url_for('admin.reports'))
        d = d.iloc[0]
        paid = dues_payments[dues_payments['dues_id'] == dues_id] if not dues_payments.empty else pd.DataFrame()
        rows = _records(paid)
        for r in rows:
            r['dues_id'] = dues_id
            r['month'] = d.get('month', '')
            r['year'] = d.get('year', '')
        return _csv_response(rows, f'dues_plan_{dues_id}_{ts}.csv')

    if kind == 'all_dues':
        return _csv_response(_records(dues_payments), f'all_dues_{ts}.csv')

    if kind == 'dues_month':
        month = request.args.get('month', '')
        year  = request.args.get('year', '')
        if not (month and year):
            flash('Month and year required.', 'danger')
            return redirect(url_for('admin.reports'))
        plans = dues_plans[(dues_plans['month'].str.lower() == month.lower()) &
                           (dues_plans['year'].astype(str) == str(year))] if not dues_plans.empty else pd.DataFrame()
        if plans.empty:
            flash(f'No dues found for {month} {year}.', 'warning')
            return redirect(url_for('admin.reports'))
        dues_ids = plans['dues_id'].tolist()
        paid = dues_payments[dues_payments['dues_id'].isin(dues_ids)] if not dues_payments.empty else pd.DataFrame()
        rows = _records(paid)
        for r in rows:
            r['month'] = month
            r['year'] = year
        return _csv_response(rows, f'dues_{month}_{year}_{ts}.csv')

    if kind == 'outstanding_dues':
        member_count = len(members)
        rows = []
        for _, d in dues_plans.iterrows():
            did = d['dues_id']
            if str(d.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            paid_ids = set(dues_payments[dues_payments['dues_id'] == did]['member_id'].tolist()) if not dues_payments.empty else set()
            unpaid = members[~members['member_id'].isin(paid_ids)] if not members.empty else pd.DataFrame()
            for _, m in unpaid.iterrows():
                rows.append({
                    'dues_id': did,
                    'month': d.get('month', ''),
                    'year': d.get('year', ''),
                    'amount_owed': d.get('amount', ''),
                    'member_id': m.get('member_id', ''),
                    'member_name': m.get('full_name', ''),
                    'email': m.get('email', ''),
                    'phone': m.get('phone', ''),
                    'house': m.get('house', ''),
                })
        return _csv_response(rows, f'outstanding_dues_{ts}.csv')

    if kind == 'top_dues_payers':
        if dues_payments.empty:
            return _csv_response([], f'top_dues_payers_{ts}.csv')
        df = dues_payments.copy()
        df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
        grouped = df.groupby(['member_id', 'member_name'])['amount'].sum().reset_index()
        grouped = grouped.sort_values('amount', ascending=False)
        rows = []
        for i, r in enumerate(grouped.to_dict('records'), 1):
            r['rank'] = i
            r['total_paid'] = r.pop('amount')
            rows.append(r)
        return _csv_response(rows, f'top_dues_payers_{ts}.csv')

    # ═══════════════════════════════════════════════════
    # CONTRIBUTIONS
    # ═══════════════════════════════════════════════════
    if kind == 'all_campaigns':
        member_count = len(members)
        rows = []
        for _, c in campaigns.iterrows():
            cid = c['campaign_id']
            target = float(c.get('target_amount', 0) or 0)
            sub = contribs[contribs['campaign_id'] == cid] if not contribs.empty else pd.DataFrame()
            raised = _amt(sub)
            paid_ids = set(sub['member_id'].tolist()) if not sub.empty else set()
            rows.append({
                'campaign_id': cid,
                'title': c['title'],
                'description': c.get('description', ''),
                'target': target,
                'raised': raised,
                'remaining': max(target - raised, 0),
                'funded_pct': round(raised / target * 100, 1) if target else 0,
                'paid_count': len(paid_ids),
                'unpaid_count': member_count - len(paid_ids),
                'total_members': member_count,
                'active': c.get('active', ''),
                'created_at': c.get('created_at', ''),
            })
        return _csv_response(rows, f'all_campaigns_{ts}.csv')

    if kind == 'campaign':
        cid = request.args.get('campaign_id', '')
        c = campaigns[campaigns['campaign_id'] == cid] if not campaigns.empty else pd.DataFrame()
        if c.empty:
            flash('Campaign not found.', 'danger')
            return redirect(url_for('admin.reports'))
        c = c.iloc[0]
        sub = contribs[contribs['campaign_id'] == cid] if not contribs.empty else pd.DataFrame()
        rows = _records(sub)
        for r in rows:
            r['campaign_id'] = cid
            r['campaign_title'] = c['title']
        return _csv_response(rows, f'campaign_{cid}_{ts}.csv')

    if kind == 'all_contributions':
        rows = _records(contribs)
        titles = {r['campaign_id']: r['title'] for _, r in campaigns.iterrows()} if not campaigns.empty else {}
        for r in rows:
            r['campaign_title'] = titles.get(r.get('campaign_id', ''), '')
        return _csv_response(rows, f'all_contributions_{ts}.csv')

    if kind == 'campaign_payments':
        cid = request.args.get('campaign_id', '')
        sub = contribs[contribs['campaign_id'] == cid] if not contribs.empty else pd.DataFrame()
        return _csv_response(_records(sub), f'campaign_payments_{cid}_{ts}.csv')

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
                    'campaign_id': cid,
                    'campaign_title': c['title'],
                    'target': c.get('target_amount', ''),
                    'member_id': m.get('member_id', ''),
                    'member_name': m.get('full_name', ''),
                    'email': m.get('email', ''),
                    'phone': m.get('phone', ''),
                    'house': m.get('house', ''),
                })
        return _csv_response(rows, f'outstanding_contribs_{ts}.csv')

    if kind == 'top_contributors':
        if contribs.empty:
            return _csv_response([], f'top_contributors_{ts}.csv')
        df = contribs.copy()
        df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
        grouped = df.groupby(['member_id', 'member_name'])['amount'].sum().reset_index()
        counts = df.groupby(['member_id'])['contribution_id'].count().reset_index(name='contributions_count')
        grouped = grouped.merge(counts, on='member_id', how='left')
        grouped = grouped.sort_values('amount', ascending=False)
        rows = []
        for i, r in enumerate(grouped.to_dict('records'), 1):
            r['rank'] = i
            r['total_contributed'] = r.pop('amount')
            rows.append(r)
        return _csv_response(rows, f'top_contributors_{ts}.csv')

    # ═══════════════════════════════════════════════════
    # MEMBERSHIP
    # ═══════════════════════════════════════════════════
    if kind == 'all_members':
        df = members.copy()
        if 'password_hash' in df.columns:
            df = df.drop(columns=['password_hash'])
        return _csv_response(_records(df), f'all_members_{ts}.csv')

    if kind == 'members_by_house':
        df = members.copy()
        if 'password_hash' in df.columns:
            df = df.drop(columns=['password_hash'])
        df['house'] = df['house'].replace('', 'Not Specified').fillna('Not Specified')
        grouped = df.groupby('house').size().reset_index(name='count')
        grouped = grouped.sort_values('count', ascending=False)
        rows = []
        for _, r in grouped.iterrows():
            house_members = df[df['house'] == r['house']]['full_name'].tolist()
            rows.append({
                'house': r['house'],
                'count': r['count'],
                'members': '; '.join(house_members),
            })
        return _csv_response(rows, f'members_by_house_{ts}.csv')

    if kind == 'members_by_year':
        df = members.copy()
        if df.empty:
            return _csv_response([], f'members_by_year_{ts}.csv')
        df['reg_year'] = df['registered_at'].str[:7]  # YYYY-MM
        grouped = df.groupby('reg_year').size().reset_index(name='count')
        grouped = grouped.sort_values('reg_year', ascending=False)
        rows = []
        for _, r in grouped.iterrows():
            names = df[df['reg_year'] == r['reg_year']]['full_name'].tolist()
            rows.append({
                'month': r['reg_year'],
                'count': r['count'],
                'members': '; '.join(names),
            })
        return _csv_response(rows, f'members_by_year_{ts}.csv')

    if kind == 'inactive_members':
        voter_ids = set(votes['member_id'].tolist()) if not votes.empty else set()
        payer_ids = set(dues_payments['member_id'].tolist()) if not dues_payments.empty else set()
        contributor_ids = set(contribs['member_id'].tolist()) if not contribs.empty else set()
        active_ids = voter_ids | payer_ids | contributor_ids
        inactive = members[~members['member_id'].isin(active_ids)] if not members.empty else pd.DataFrame()
        df = inactive.copy()
        if 'password_hash' in df.columns:
            df = df.drop(columns=['password_hash'])
        return _csv_response(_records(df), f'inactive_members_{ts}.csv')

    if kind == 'contact_directory':
        if members.empty:
            return _csv_response([], f'contact_directory_{ts}.csv')
        df = members[['full_name', 'email', 'phone', 'house']].copy()
        return _csv_response(_records(df), f'contact_directory_{ts}.csv')

    # ═══════════════════════════════════════════════════
    # COMBINED
    # ═══════════════════════════════════════════════════
    if kind == 'master_financial':
        rows = []
        for _, r in dues_payments.iterrows():
            rows.append({
                'date': r.get('created_at', ''),
                'type': 'Dues',
                'reference': r.get('dues_id', ''),
                'member_name': r.get('member_name', ''),
                'amount': r.get('amount', ''),
                'method': r.get('method', ''),
            })
        for _, r in contribs.iterrows():
            rows.append({
                'date': r.get('created_at', ''),
                'type': 'Contribution',
                'reference': r.get('campaign_id', ''),
                'member_name': r.get('member_name', ''),
                'amount': r.get('amount', ''),
                'method': r.get('method', ''),
            })
        rows.sort(key=lambda x: x['date'])
        return _csv_response(rows, f'master_financial_{ts}.csv')

    if kind == 'executive_summary':
        member_count = len(members)
        total_dues = _amt(dues_payments)
        total_contribs = _amt(contribs)
        total_votes = len(votes)

        # Top 10 contributors
        top_c = []
        if not contribs.empty:
            df = contribs.copy()
            df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
            g = df.groupby(['member_name'])['amount'].sum().sort_values(ascending=False).head(10)
            top_c = [f'{name}: GH₵{amt:.2f}' for name, amt in g.items()]

        top_d = []
        if not dues_payments.empty:
            df = dues_payments.copy()
            df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
            g = df.groupby(['member_name'])['amount'].sum().sort_values(ascending=False).head(10)
            top_d = [f'{name}: GH₵{amt:.2f}' for name, amt in g.items()]

        rows = [
            {'metric': 'Total Members', 'value': member_count},
            {'metric': 'Total Dues Collected', 'value': f'GH₵{total_dues:.2f}'},
            {'metric': 'Total Contributions', 'value': f'GH₵{total_contribs:.2f}'},
            {'metric': 'Total Money Collected', 'value': f'GH₵{total_dues + total_contribs:.2f}'},
            {'metric': 'Total Votes Cast', 'value': total_votes},
            {'metric': 'Total Polls', 'value': len(polls)},
            {'metric': 'Total Campaigns', 'value': len(campaigns)},
            {'metric': 'Total Dues Periods', 'value': len(dues_plans)},
            {'metric': 'Top 10 Contributors', 'value': ' | '.join(top_c)},
            {'metric': 'Top 10 Dues Payers', 'value': ' | '.join(top_d)},
            {'metric': 'Report Generated', 'value': datetime.now().isoformat()},
        ]
        return _csv_response(rows, f'executive_summary_{ts}.csv')

    # ═══════════════════════════════════════════════════
    # UNKNOWN
    # ═══════════════════════════════════════════════════
    flash(f'Unknown report: {kind}', 'danger')
    return redirect(url_for('admin.reports'))


# ═══════════════════════════════════════════════════════════
# FULL BACKUP (ZIP of all tables as CSVs)
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
        for table_name, csv_path in tables:
            df = _load(table_name, csv_path)
            if df.empty:
                continue
            csv_text = df.to_csv(index=False)
            zf.writestr(f'{table_name}_{ts}.csv', csv_text)
        zf.writestr('README.txt',
                    f'ODADEAƐ07 Backup\n'
                    f'Generated: {datetime.now().isoformat()}\n'
                    f'Source: {"Supabase" if sb.SUPABASE_ENABLED else "Local CSV"}\n'
                    f'Tables: {len(tables)}\n')
    buf.seek(0)
    return send_file(buf, mimetype='application/zip',
                     as_attachment=True,
                     download_name=f'odadea07_backup_{ts}.zip')


# ═══════════════════════════════════════════════════════════
# LEGACY DOWNLOAD ROUTE (kept for the old Reports page buttons)
# ═══════════════════════════════════════════════════════════
@admin_bp.route('/download/<kind>')
@_admin_required
def download(kind):
    """Redirect old /download/<kind> URLs to the new /report/<kind>."""
    mapping = {
        'members':       'all_members',
        'contributions': 'all_contributions',
        'dues':          'all_dues',
        'votes':         'all_votes',
        'polls':         'all_polls',
        'campaigns':     'all_campaigns',
        'dues_plans':    'all_dues_plans',
    }
    new_kind = mapping.get(kind)
    if not new_kind:
        flash(f'Unknown report: {kind}', 'danger')
        return redirect(url_for('admin.reports'))
    return redirect(url_for('admin.report', kind=new_kind))