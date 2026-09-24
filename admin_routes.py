"""
admin_routes.py — ODADEAƐ07 Admin Panel (Secured)

Mounted at /admin by app.py.

Security:
  • CSRF tokens on every POST form
  • Admin-login rate limiting (5 attempts / 15 min)
  • Session cookies: Secure, HttpOnly, SameSite=Lax
  • All inputs sanitized and length-capped
  • Append-only data writes; deletions are explicit
"""

import os
import io
import csv
import json
import time
import random
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

import pandas as pd
from flask import (Blueprint, render_template_string, request, session,
                   redirect, url_for, flash, send_file, make_response)
from flask_wtf.csrf import generate_csrf

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
# RATE LIMITER (admin login)
# ─────────────────────────────────────────────────────────
_admin_attempts = defaultdict(list)
_WINDOW  = timedelta(minutes=15)
_MAX     = 5


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
# DATA HELPERS (append-only)
# ─────────────────────────────────────────────────────────
def _load(path):
    if os.path.exists(path):
        return pd.read_csv(path, dtype=str).fillna('')
    return pd.DataFrame()


def _save(path, df):
    df.to_csv(path, index=False)


def _append(path, row):
    df = _load(path)
    new = pd.DataFrame([row])
    out = pd.concat([df, new], ignore_index=True) if not df.empty else new
    _save(path, out)


def _delete_where(path, col, val):
    df = _load(path)
    if df.empty or col not in df.columns:
        return False
    before = len(df)
    df = df[df[col].astype(str) != str(val)]
    if len(df) == before:
        return False
    _save(path, df)
    return True


def _update_where(path, id_col, id_val, updates):
    df = _load(path)
    if df.empty or id_col not in df.columns:
        return False
    mask = df[id_col].astype(str) == str(id_val)
    if not mask.any():
        return False
    for k, v in updates.items():
        df.loc[mask, k] = v
    _save(path, df)
    return True


def _sanitize(s, max_len=200):
    if s is None:
        return ''
    s = str(s).strip().replace('\r', '').replace('\n', '').replace('\x00', '')
    return s[:max_len]


def _csv_bytes(rows):
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return buf.getvalue().encode('utf-8')


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
    </div>
</footer>
</body>
</html>
"""


def _page(body):
    return render_template_string(ADMIN_LAYOUT, body=body, csrf_token=generate_csrf)


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
        if remaining > 0:
            flash(f'Wrong password. {remaining} attempts left.', 'danger')
        else:
            flash('Too many failed attempts. Locked for 15 minutes.', 'danger')

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
    members = _load(MEMBERS_FILE)
    polls   = _load(POLLS_FILE)
    votes   = _load(VOTES_FILE)
    contrib = _load(CONTRIBUTIONS_FILE)
    camps   = _load(CAMPAIGNS_FILE)
    dues    = _load(DUES_FILE)
    duesc   = _load(DUES_CAMPAIGNS_FILE)

    def _sum(df):
        if df.empty or 'amount' not in df.columns:
            return 0.0
        return float(pd.to_numeric(df['amount'], errors='coerce').fillna(0).sum())

    stats = {
        'members': len(members),
        'polls':   len(polls),
        'votes':   len(votes),
        'contrib_total': _sum(contrib),
        'camps':   len(camps),
        'dues_total': _sum(dues),
        'dues_plans': len(duesc),
    }
    body = render_template_string("""
    <div class="reports-header">
      <div><h1>🛡️ Admin Dashboard</h1>
      <p class="subtitle">Full control • live data</p></div>
      <div class="report-actions">
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
    </div>
    """, s=stats)
    return _page(body)


# ─────────────────────────────────────────────────────────
# POLLS
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
                _append(POLLS_FILE, {
                    'poll_id': f"POLL{int(time.time())}_{random.randint(100,999)}",
                    'title': title,
                    'description': desc,
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
            if pid and _delete_where(POLLS_FILE, 'poll_id', pid):
                _delete_where(VOTES_FILE, 'poll_id', pid)
                flash('Poll and its votes deleted.', 'success')
            else:
                flash('Poll not found.', 'danger')

        elif action == 'toggle':
            pid = request.form.get('poll_id')
            df = _load(POLLS_FILE)
            if pid and not df.empty:
                row = df[df['poll_id'] == pid]
                if not row.empty:
                    cur = str(row.iloc[0]['active']).lower() in ['true', '1', 'yes']
                    _update_where(POLLS_FILE, 'poll_id', pid, {'active': str(not cur)})
                    flash(f'Poll {"closed" if cur else "re-opened"}.', 'success')

        return redirect(url_for('admin.polls'))

    polls_df = _load(POLLS_FILE)
    votes_df = _load(VOTES_FILE)
    member_count = len(_load(MEMBERS_FILE))

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
        <a href="{{ url_for('admin.download', kind='polls') }}" class="btn btn-secondary">⬇ Polls CSV</a>
        <a href="{{ url_for('admin.download', kind='votes') }}" class="btn btn-secondary">⬇ Votes CSV</a>
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

      <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-top:1rem; padding-top:1rem; border-top:1px dashed var(--gray-200);">
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
                _append(CAMPAIGNS_FILE, {
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
            if cid and _delete_where(CAMPAIGNS_FILE, 'campaign_id', cid):
                _delete_where(CONTRIBUTIONS_FILE, 'campaign_id', cid)
                flash('Campaign and its payments deleted.', 'success')
            else:
                flash('Campaign not found.', 'danger')

        elif action == 'toggle':
            cid = request.form.get('campaign_id')
            df = _load(CAMPAIGNS_FILE)
            if cid and not df.empty:
                row = df[df['campaign_id'] == cid]
                if not row.empty:
                    cur = str(row.iloc[0]['active']).lower() in ['true', '1', 'yes']
                    _update_where(CAMPAIGNS_FILE, 'campaign_id', cid, {'active': str(not cur)})
                    flash(f'Campaign {"closed" if cur else "re-opened"}.', 'success')

        return redirect(url_for('admin.contrib'))

    camps = _load(CAMPAIGNS_FILE)
    payments = _load(CONTRIBUTIONS_FILE)
    member_count = len(_load(MEMBERS_FILE))

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
        <a href="{{ url_for('admin.download', kind='contributions') }}" class="btn btn-secondary">⬇ Contributions CSV</a>
        <a href="{{ url_for('admin.download', kind='campaigns') }}" class="btn btn-secondary">⬇ Campaigns CSV</a>
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
                _append(DUES_CAMPAIGNS_FILE, {
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
            if did and _delete_where(DUES_CAMPAIGNS_FILE, 'dues_id', did):
                _delete_where(DUES_FILE, 'dues_id', did)
                flash('Dues period and payments deleted.', 'success')
            else:
                flash('Dues period not found.', 'danger')

        elif action == 'toggle':
            did = request.form.get('dues_id')
            df = _load(DUES_CAMPAIGNS_FILE)
            if did and not df.empty:
                row = df[df['dues_id'] == did]
                if not row.empty:
                    cur = str(row.iloc[0]['active']).lower() in ['true', '1', 'yes']
                    _update_where(DUES_CAMPAIGNS_FILE, 'dues_id', did, {'active': str(not cur)})
                    flash(f'Dues {"closed" if cur else "re-opened"}.', 'success')

        return redirect(url_for('admin.dues'))

    plans = _load(DUES_CAMPAIGNS_FILE)
    payments = _load(DUES_FILE)
    member_count = len(_load(MEMBERS_FILE))

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
        <a href="{{ url_for('admin.download', kind='dues') }}" class="btn btn-secondary">⬇ Dues CSV</a>
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
# MEMBERS (add / edit / delete)
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
                _append(MEMBERS_FILE, {
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
            if mid and _update_where(MEMBERS_FILE, 'member_id', mid, updates):
                flash('Member updated.', 'success')
            else:
                flash('Member not found.', 'danger')

        elif action == 'delete':
            mid = request.form.get('member_id')
            if mid and _delete_where(MEMBERS_FILE, 'member_id', mid):
                flash('Member deleted.', 'success')
            else:
                flash('Member not found.', 'danger')

        return redirect(url_for('admin.members'))

    df = _load(MEMBERS_FILE)
    rows = df.to_dict('records') if not df.empty else []
    for r in rows:
        r.pop('password_hash', None)

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>👥 Members ({{ rows|length }})</h1></div>
      <div class="report-actions">
        <a href="{{ url_for('admin.download', kind='members') }}" class="btn btn-secondary">⬇ CSV</a>
        <a href="{{ url_for('admin.home') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container">
      <h1>➕ Add Member</h1>
      <p class="form-subtitle">Default password: changeme123 — ask them to reset after login</p>
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


# ─────────────────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────────────────
@admin_bp.route('/reports')
@_admin_required
def reports():
    members = _load(MEMBERS_FILE)
    contrib = _load(CONTRIBUTIONS_FILE)
    dues    = _load(DUES_FILE)
    votes   = _load(VOTES_FILE)
    polls   = _load(POLLS_FILE)

    def _sum(df):
        if df.empty or 'amount' not in df.columns:
            return 0.0
        return float(pd.to_numeric(df['amount'], errors='coerce').fillna(0).sum())

    body = render_template_string("""
    <div class="reports-header">
      <div><h1>📈 Reports & Downloads</h1>
      <p class="subtitle">Every data set — downloadable as CSV</p></div>
      <div class="report-actions">
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

    <div class="report-cards-grid">
      <div class="report-card">
        <h3>👥 Membership</h3>
        <p>All registered members.</p>
        <a href="{{ url_for('admin.download', kind='members') }}" class="btn btn-primary">⬇ Members CSV</a>
      </div>
      <div class="report-card">
        <h3>🗳️ Voting Results</h3>
        <p>Every vote with member and poll.</p>
        <a href="{{ url_for('admin.download', kind='votes') }}" class="btn btn-primary">⬇ Votes CSV</a>
        <a href="{{ url_for('admin.download', kind='polls') }}" class="btn btn-secondary">⬇ Polls CSV</a>
      </div>
      <div class="report-card">
        <h3>🎯 Contributions</h3>
        <p>Every contribution and campaign.</p>
        <a href="{{ url_for('admin.download', kind='contributions') }}" class="btn btn-primary">⬇ Contributions</a>
        <a href="{{ url_for('admin.download', kind='campaigns') }}" class="btn btn-secondary">⬇ Campaigns</a>
      </div>
      <div class="report-card">
        <h3>📅 Dues</h3>
        <p>Every dues payment and period.</p>
        <a href="{{ url_for('admin.download', kind='dues') }}" class="btn btn-primary">⬇ Dues CSV</a>
        <a href="{{ url_for('admin.download', kind='dues_plans') }}" class="btn btn-secondary">⬇ Periods CSV</a>
      </div>
    </div>
    """, member_count=len(members), contrib_total=_sum(contrib),
         dues_total=_sum(dues), votes_count=len(votes), polls_count=len(polls))
    return _page(body)


# ─────────────────────────────────────────────────────────
# DOWNLOAD
# ─────────────────────────────────────────────────────────
@admin_bp.route('/download/<kind>')
@_admin_required
def download(kind):
    files = {
        'members':       MEMBERS_FILE,
        'contributions': CONTRIBUTIONS_FILE,
        'dues':          DUES_FILE,
        'votes':         VOTES_FILE,
        'polls':         POLLS_FILE,
        'campaigns':     CAMPAIGNS_FILE,
        'dues_plans':    DUES_CAMPAIGNS_FILE,
    }
    path = files.get(kind)
    if not path or not os.path.exists(path):
        flash(f'No data for "{kind}".', 'danger')
        return redirect(url_for('admin.reports'))
    return send_file(
        path,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'odadea07_{kind}_{datetime.now().strftime("%Y%m%d")}.csv'
    )