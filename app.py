"""
app.py — ODADEAƐ07 Main Application

Features:
  • Home page (hero + stats)
  • Member registration
  • Member login / logout
  • Member dashboard
  • Polls — view active polls, cast a vote
  • Dues — view active dues periods, pay
  • Contributions — view campaigns, contribute
  • Admin panel mounted at /admin (from admin_routes.py)

Data: all CSV files in ./data/. Files are APPEND-ONLY — never overwritten.
"""

import os
import json
import time
import random
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template_string, request, session, redirect,
                   url_for, flash, send_file, jsonify)
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash

# ═══════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
os.makedirs(DATA_DIR, exist_ok=True)

MEMBERS_FILE        = os.path.join(DATA_DIR, 'members.csv')
POLLS_FILE          = os.path.join(DATA_DIR, 'polls.csv')
VOTES_FILE          = os.path.join(DATA_DIR, 'votes.csv')
CONTRIBUTIONS_FILE  = os.path.join(DATA_DIR, 'contributions.csv')
CAMPAIGNS_FILE      = os.path.join(DATA_DIR, 'contributions_campaigns.csv')
DUES_FILE           = os.path.join(DATA_DIR, 'dues.csv')
DUES_CAMPAIGNS_FILE = os.path.join(DATA_DIR, 'dues_campaigns.csv')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production-please')
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 7

# ═══════════════════════════════════════════════════════════
# ADMIN PANEL MOUNT  ← 6-line wiring
# ═══════════════════════════════════════════════════════════
from admin_routes import admin_bp
app.register_blueprint(admin_bp)


# ═══════════════════════════════════════════════════════════
# DATA HELPERS  (append-only, never mutate existing rows)
# ═══════════════════════════════════════════════════════════
def load_csv(path):
    """Read a CSV. Returns empty DataFrame if the file doesn't exist."""
    if os.path.exists(path):
        return pd.read_csv(path, dtype=str).fillna('')
    return pd.DataFrame()


def append_row(path, row):
    """Add a row to the end of a CSV. Existing rows untouched."""
    df = load_csv(path)
    new = pd.DataFrame([row])
    out = pd.concat([df, new], ignore_index=True) if not df.empty else new
    out.to_csv(path, index=False)


def member_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get('member_id'):
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper


def current_member():
    if not session.get('member_id'):
        return None
    df = load_csv(MEMBERS_FILE)
    if df.empty:
        return None
    row = df[df['member_id'].astype(str) == str(session['member_id'])]
    return row.iloc[0].to_dict() if not row.empty else None


# ═══════════════════════════════════════════════════════════
# LAYOUT (uses your existing style.css — no templates folder)
# ═══════════════════════════════════════════════════════════
PUBLIC_LAYOUT = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ODADEAƐ07 — PRESEC 2007 Year Group</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
<header class="main-header">
    <div class="header-content">
        <a href="{{ url_for('index') }}" class="logo-section">
            <img src="{{ url_for('static', filename='images/presec-badge.png') }}"
                 class="school-badge" onerror="this.style.display='none'">
            <div class="logo-text">
                <h1>ODADEAƐ07</h1>
                <p>PRESEC 2007 Year Group</p>
            </div>
        </a>
        <nav class="main-nav">
            <a href="{{ url_for('index') }}">🏠 Home</a>
            {% if session.member_id %}
                <a href="{{ url_for('dashboard') }}">📊 Dashboard</a>
                <a href="{{ url_for('polls_page') }}">🗳️ Polls</a>
                <a href="{{ url_for('dues_page') }}">📅 Dues</a>
                <a href="{{ url_for('contributions_page') }}">🎯 Contribute</a>
                <a href="{{ url_for('logout') }}" class="btn-logout">Logout</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}" class="btn-register">Register</a>
            {% endif %}
            {% if session.is_admin %}
                <a href="{{ url_for('admin.home') }}" class="btn-register">🛡️ Admin</a>
            {% else %}
                <a href="{{ url_for('admin.login') }}" class="btn-logout">Admin</a>
            {% endif %}
        </nav>
    </div>
</header>

{% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        <div class="flash-messages">
            {% for category, message in messages %}
                <div class="flash flash-{{ category }}">{{ message }}</div>
            {% endfor %}
        </div>
    {% endif %}
{% endwith %}

<main class="main-content">
    {{ body|safe }}
</main>

<footer class="main-footer">
    <div class="footer-content">
        <p><strong>ODADEAƐ07</strong> — PRESEC 2007 Year Group</p>
        <p class="motto">"In Lumine Tuo Videbimus Lumen"</p>
        <p>© {{ year }} ODADEAƐ07. All rights reserved.</p>
    </div>
</footer>
</body>
</html>
"""


def page(body):
    return render_template_string(PUBLIC_LAYOUT, body=body, year=datetime.now().year)


# ═══════════════════════════════════════════════════════════
# HOME
# ═══════════════════════════════════════════════════════════
@app.route('/')
def index():
    members = load_csv(MEMBERS_FILE)
    polls   = load_csv(POLLS_FILE)
    camps   = load_csv(CAMPAIGNS_FILE)

    body = render_template_string("""
    <div class="hero-section">
      <div class="hero-content">
        <img src="{{ url_for('static', filename='images/presec-badge.png') }}"
             class="school-badge" alt="PRESEC" onerror="this.style.display='none'">
        <h1>ODADEAƐ07</h1>
        <p class="hero-subtitle">Presbyterian Boys' Secondary School • Class of 2007</p>
        <p class="hero-motto">"In Lumine Tuo Videbimus Lumen"</p>

        <div class="hero-stats">
          <div class="stat-card">
            <span class="stat-number">{{ members }}</span>
            <span class="stat-label">Members</span>
          </div>
          <div class="stat-card">
            <span class="stat-number">{{ polls }}</span>
            <span class="stat-label">Polls</span>
          </div>
          <div class="stat-card">
            <span class="stat-number">{{ camps }}</span>
            <span class="stat-label">Campaigns</span>
          </div>
        </div>

        <div class="hero-actions">
          {% if session.member_id %}
            <a href="{{ url_for('dashboard') }}" class="btn btn-primary">Go to Dashboard</a>
          {% else %}
            <a href="{{ url_for('register') }}" class="btn btn-primary">Register</a>
            <a href="{{ url_for('login') }}" class="btn btn-secondary">Login</a>
          {% endif %}
        </div>
      </div>
    </div>
    """, members=len(members), polls=len(polls), camps=len(camps))
    return page(body)


# ═══════════════════════════════════════════════════════════
# REGISTER
# ═══════════════════════════════════════════════════════════
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email     = request.form.get('email', '').strip().lower()
        phone     = request.form.get('phone', '').strip()
        house     = request.form.get('house', '').strip()
        password  = request.form.get('password', '')
        confirm   = request.form.get('confirm_password', '')

        if not (full_name and email and password):
            flash('Name, email and password are required.', 'danger')
            return redirect(url_for('register'))
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        members = load_csv(MEMBERS_FILE)
        if not members.empty and 'email' in members.columns:
            if email in members['email'].astype(str).str.lower().values:
                flash('That email is already registered. Please log in.', 'warning')
                return redirect(url_for('login'))

        member_id = f"MEM{int(time.time())}{random.randint(100,999)}"
        append_row(MEMBERS_FILE, {
            'member_id':     member_id,
            'full_name':     full_name,
            'email':         email,
            'phone':         phone,
            'house':         house,
            'password_hash': generate_password_hash(password),
            'registered_at': datetime.now().isoformat(),
        })
        flash(f'Welcome, {full_name}! Please log in.', 'success')
        return redirect(url_for('login'))

    body = render_template_string("""
    <div class="form-container">
      <h1>Join ODADEAƐ07</h1>
      <p class="form-subtitle">Register to vote, pay dues and contribute</p>
      <form method="POST">
        <div class="form-group">
          <label>Full Name *</label>
          <input name="full_name" required maxlength="120">
        </div>
        <div class="form-group">
          <label>Email *</label>
          <input type="email" name="email" required>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Phone</label>
            <input name="phone" placeholder="e.g. 024 000 0000">
          </div>
          <div class="form-group">
            <label>House</label>
            <input name="house" placeholder="e.g. Akro, Labone">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Password *</label>
            <input type="password" name="password" required minlength="6">
          </div>
          <div class="form-group">
            <label>Confirm Password *</label>
            <input type="password" name="confirm_password" required minlength="6">
          </div>
        </div>
        <button class="btn btn-primary btn-full">Register</button>
      </form>
      <p class="form-footer">
        Already registered? <a href="{{ url_for('login') }}">Log in</a>
      </p>
    </div>
    """)
    return page(body)


# ═══════════════════════════════════════════════════════════
# LOGIN
# ═══════════════════════════════════════════════════════════
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        pwd   = request.form.get('password', '')

        members = load_csv(MEMBERS_FILE)
        if not members.empty and 'email' in members.columns:
            row = members[members['email'].astype(str).str.lower() == email]
            if not row.empty:
                stored = row.iloc[0].get('password_hash', '')
                try:
                    if stored and check_password_hash(stored, pwd):
                        session['member_id'] = row.iloc[0]['member_id']
                        session.permanent = True
                        flash(f'Welcome back, {row.iloc[0].get("full_name","")}!', 'success')
                        return redirect(url_for('dashboard'))
                except Exception:
                    pass
        flash('Invalid email or password.', 'danger')

    body = render_template_string("""
    <div class="form-container">
      <h1>Member Login</h1>
      <form method="POST">
        <div class="form-group">
          <label>Email</label>
          <input type="email" name="email" required autofocus>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" required>
        </div>
        <button class="btn btn-primary btn-full">Log In</button>
      </form>
      <p class="form-footer">
        New here? <a href="{{ url_for('register') }}">Register</a>
      </p>
    </div>
    """)
    return page(body)


@app.route('/logout')
def logout():
    session.pop('member_id', None)
    flash('Logged out. See you soon!', 'info')
    return redirect(url_for('index'))


# ═══════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════
@app.route('/dashboard')
@member_required
def dashboard():
    m = current_member()
    if not m:
        session.pop('member_id', None)
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    dues = load_csv(DUES_FILE)
    votes = load_csv(VOTES_FILE)
    contrib = load_csv(CONTRIBUTIONS_FILE)

    my_dues  = dues[dues['member_id'].astype(str) == str(m['member_id'])] if not dues.empty and 'member_id' in dues.columns else pd.DataFrame()
    my_votes = votes[votes['member_id'].astype(str) == str(m['member_id'])] if not votes.empty and 'member_id' in votes.columns else pd.DataFrame()
    my_conts = contrib[contrib['member_id'].astype(str) == str(m['member_id'])] if not contrib.empty and 'member_id' in contrib.columns else pd.DataFrame()

    def _sum(df):
        if df.empty or 'amount' not in df.columns:
            return 0.0
        return float(pd.to_numeric(df['amount'], errors='coerce').fillna(0).sum())

    body = render_template_string("""
    <div class="dashboard-header">
      <div>
        <h1>Welcome, {{ m.full_name }}</h1>
        <p>{{ m.email }}{% if m.house %} • {{ m.house }} House{% endif %}</p>
      </div>
      <div class="member-info">
        <div class="member-photo-placeholder">{{ m.full_name[0]|upper }}</div>
      </div>
    </div>

    <div class="report-stats-grid">
      <div class="report-stat-card">
        <div class="stat-icon">📅</div>
        <div class="stat-value">GH₵{{ "%.2f"|format(dues_paid) }}</div>
        <div class="stat-title">Dues Paid</div>
        <div class="stat-sub">{{ dues_count }} payment(s)</div>
      </div>
      <div class="report-stat-card">
        <div class="stat-icon">🎯</div>
        <div class="stat-value">GH₵{{ "%.2f"|format(contrib_paid) }}</div>
        <div class="stat-title">Contributed</div>
        <div class="stat-sub">{{ contrib_count }} gift(s)</div>
      </div>
      <div class="report-stat-card">
        <div class="stat-icon">🗳️</div>
        <div class="stat-value">{{ votes_count }}</div>
        <div class="stat-title">Votes Cast</div>
      </div>
    </div>

    <div class="admin-actions">
      <a href="{{ url_for('polls_page') }}" class="btn btn-primary">🗳️ Go to Polls</a>
      <a href="{{ url_for('dues_page') }}" class="btn btn-primary">📅 Pay Dues</a>
      <a href="{{ url_for('contributions_page') }}" class="btn btn-primary">🎯 Contribute</a>
    </div>
    """, m=m,
         dues_paid=_sum(my_dues), dues_count=len(my_dues),
         contrib_paid=_sum(my_conts), contrib_count=len(my_conts),
         votes_count=len(my_votes))
    return page(body)


# ═══════════════════════════════════════════════════════════
# POLLS
# ═══════════════════════════════════════════════════════════
@app.route('/polls', methods=['GET', 'POST'])
@member_required
def polls_page():
    if request.method == 'POST':
        poll_id   = request.form.get('poll_id')
        option_id = request.form.get('option_id')
        if poll_id and option_id:
            votes = load_csv(VOTES_FILE)
            if not votes.empty and 'poll_id' in votes.columns:
                already = ((votes['poll_id'].astype(str) == str(poll_id)) &
                           (votes['member_id'].astype(str) == str(session['member_id']))).any()
            else:
                already = False

            if already:
                flash('You have already voted in this poll.', 'warning')
            else:
                m = current_member()
                append_row(VOTES_FILE, {
                    'vote_id':     f"V{int(time.time())}{random.randint(100,999)}",
                    'poll_id':     poll_id,
                    'option_id':   option_id,
                    'member_id':   session['member_id'],
                    'member_name': m['full_name'] if m else '',
                    'voted_at':    datetime.now().isoformat(),
                })
                flash('✅ Vote recorded. Thank you!', 'success')
        return redirect(url_for('polls_page'))

    polls = load_csv(POLLS_FILE)
    votes = load_csv(VOTES_FILE)

    my_votes = set()
    if not votes.empty and 'member_id' in votes.columns:
        my_votes = set(votes[votes['member_id'].astype(str) == str(session['member_id'])]['poll_id'].astype(str).tolist())

    poll_list = []
    if not polls.empty:
        for _, p in polls.iterrows():
            if str(p.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            try:
                opts = json.loads(p.get('options_json', '[]'))
            except Exception:
                opts = []
            poll_list.append({
                'id': p['poll_id'],
                'title': p.get('title', ''),
                'description': p.get('description', ''),
                'options': opts,
                'voted': str(p['poll_id']) in my_votes,
            })

    body = render_template_string("""
    <div class="reports-header">
      <div>
        <h1>🗳️ Active Polls</h1>
        <p class="subtitle">{{ polls|length }} open</p>
      </div>
    </div>

    {% for p in polls %}
    <div class="poll-item">
      <h3>{{ p.title }}</h3>
      <p>{{ p.description }}</p>
      {% if p.voted %}
        <span class="voted-badge">✅ You voted</span>
      {% else %}
        <form method="POST">
          <input type="hidden" name="poll_id" value="{{ p.id }}">
          <div class="vote-options">
            {% for o in p.options %}
            <label class="vote-option">
              <input type="radio" name="option_id" value="{{ o.id }}" required>
              <span class="option-text">{{ o.text }}</span>
            </label>
            {% endfor %}
          </div>
          <button class="btn btn-primary">Cast Vote</button>
        </form>
      {% endif %}
    </div>
    {% else %}
    <p class="empty-state">No active polls right now. Check back soon.</p>
    {% endfor %}
    """, polls=poll_list)
    return page(body)


# ═══════════════════════════════════════════════════════════
# DUES
# ═══════════════════════════════════════════════════════════
@app.route('/dues', methods=['GET', 'POST'])
@member_required
def dues_page():
    if request.method == 'POST':
        dues_id = request.form.get('dues_id')
        try:
            amount = float(request.form.get('amount', 0) or 0)
        except ValueError:
            amount = 0
        method = request.form.get('method', 'Mobile Money')

        if dues_id and amount > 0:
            m = current_member()
            append_row(DUES_FILE, {
                'payment_id':  f"D{int(time.time())}{random.randint(100,999)}",
                'dues_id':     dues_id,
                'member_id':   session['member_id'],
                'member_name': m['full_name'] if m else '',
                'amount':      amount,
                'method':      method,
                'note':        '',
                'created_at':  datetime.now().isoformat(),
            })
            flash('✅ Dues payment recorded.', 'success')
        else:
            flash('Invalid amount.', 'danger')
        return redirect(url_for('dues_page'))

    plans = load_csv(DUES_CAMPAIGNS_FILE)
    dues  = load_csv(DUES_FILE)

    my_paid = set()
    if not dues.empty and 'member_id' in dues.columns:
        my_paid = set(dues[dues['member_id'].astype(str) == str(session['member_id'])]['dues_id'].astype(str).tolist())

    rows = []
    if not plans.empty:
        for _, d in plans.iterrows():
            if str(d.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            try:
                amt = float(d.get('amount', 0) or 0)
            except ValueError:
                amt = 0
            rows.append({
                'id': f"{d.get('month','')} {d.get('year','')}",
                'dues_id': d['dues_id'],
                'label': f"{d.get('month','')} {d.get('year','')}",
                'amount': amt,
                'paid': str(d['dues_id']) in my_paid,
            })

    body = render_template_string("""
    <div class="reports-header">
      <div>
        <h1>📅 Dues</h1>
        <p class="subtitle">{{ plans|length }} period(s) open</p>
      </div>
    </div>

    {% for d in plans %}
    <div class="poll-item">
      <h3>{{ d.label }} — GH₵{{ "%.2f"|format(d.amount) }}</h3>
      {% if d.paid %}
        <span class="voted-badge">✅ Paid</span>
      {% else %}
        <form method="POST">
          <input type="hidden" name="dues_id" value="{{ d.dues_id }}">
          <div class="form-group">
            <label>Amount (GH₵)</label>
            <input type="number" step="0.01" name="amount"
                   value="{{ d.amount }}" required>
          </div>
          <div class="form-group">
            <label>Method</label>
            <select name="method">
              <option>Mobile Money</option>
              <option>Bank Transfer</option>
              <option>Cash</option>
            </select>
          </div>
          <button class="btn btn-primary">Pay Dues</button>
        </form>
      {% endif %}
    </div>
    {% else %}
    <p class="empty-state">No dues periods open right now.</p>
    {% endfor %}
    """, plans=rows)
    return page(body)


# ═══════════════════════════════════════════════════════════
# CONTRIBUTIONS
# ═══════════════════════════════════════════════════════════
@app.route('/contributions', methods=['GET', 'POST'])
@member_required
def contributions_page():
    if request.method == 'POST':
        cid = request.form.get('campaign_id')
        try:
            amount = float(request.form.get('amount', 0) or 0)
        except ValueError:
            amount = 0
        method = request.form.get('method', 'Mobile Money')

        if cid and amount > 0:
            m = current_member()
            append_row(CONTRIBUTIONS_FILE, {
                'contribution_id': f"C{int(time.time())}{random.randint(100,999)}",
                'campaign_id':     cid,
                'member_id':       session['member_id'],
                'member_name':     m['full_name'] if m else '',
                'amount':          amount,
                'method':          method,
                'note':            '',
                'created_at':      datetime.now().isoformat(),
            })
            flash('✅ Contribution recorded. Thank you!', 'success')
        else:
            flash('Invalid amount.', 'danger')
        return redirect(url_for('contributions_page'))

    camps    = load_csv(CAMPAIGNS_FILE)
    contribs = load_csv(CONTRIBUTIONS_FILE)

    rows = []
    if not camps.empty:
        for _, c in camps.iterrows():
            if str(c.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            raised = 0.0
            if not contribs.empty and 'campaign_id' in contribs.columns:
                sub = contribs[contribs['campaign_id'].astype(str) == str(c['campaign_id'])]
                raised = float(pd.to_numeric(sub['amount'], errors='coerce').fillna(0).sum())
            try:
                target = float(c.get('target_amount', 0) or 0)
            except ValueError:
                target = 0
            rows.append({
                'id': c['campaign_id'],
                'title': c.get('title', ''),
                'description': c.get('description', ''),
                'raised': raised,
                'target': target,
                'pct': min(raised / target * 100, 100) if target else 0,
            })

    body = render_template_string("""
    <div class="reports-header">
      <div>
        <h1>🎯 Contributions</h1>
        <p class="subtitle">{{ camps|length }} campaign(s) active</p>
      </div>
    </div>

    {% for c in camps %}
    <div class="poll-item">
      <h3>{{ c.title }}</h3>
      <p>{{ c.description }}</p>
      <div class="progress-track">
        <div class="progress-fill" style="width: {{ c.pct }}%"></div>
      </div>
      <p style="margin-top:0.75rem;">
        GH₵{{ "%.2f"|format(c.raised) }} raised of
        GH₵{{ "%.2f"|format(c.target) }}
      </p>
      <form method="POST">
        <input type="hidden" name="campaign_id" value="{{ c.id }}">
        <div class="form-group">
          <label>Amount (GH₵)</label>
          <input type="number" step="0.01" name="amount" required>
        </div>
        <div class="form-group">
          <label>Method</label>
          <select name="method">
            <option>Mobile Money</option>
            <option>Bank Transfer</option>
            <option>Cash</option>
          </select>
        </div>
        <button class="btn btn-primary">Contribute</button>
      </form>
    </div>
    {% else %}
    <p class="empty-state">No campaigns are open right now.</p>
    {% endfor %}
    """, camps=rows)
    return page(body)


# ═══════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'time': datetime.now().isoformat(),
        'data_dir': DATA_DIR,
    })


# ═══════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 ODADEAƐ07 — Main App")
    print("=" * 60)
    print(f"📁 Data folder: {DATA_DIR}")
    print(f"🌐 Open:        http://localhost:5000")
    print(f"🛡️  Admin:       http://localhost:5000/admin/login")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
