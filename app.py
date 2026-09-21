"""
app.py — ODADEAƐ07 Main Application (Admin-enabled)

Includes:
  • Member register / login
  • Cast vote on active polls
  • Pay dues
  • Make contribution
  • Full admin panel mounted at /admin (from admin_routes.py)

Data: all CSV files in ./data/. Never overwritten — only appended.
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
# ADMIN PANEL MOUNT  ← the only admin wiring you need
# ═══════════════════════════════════════════════════════════
from admin_routes import admin_bp
app.register_blueprint(admin_bp)


# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════
def load_csv(path):
    if os.path.exists(path):
        return pd.read_csv(path).fillna('')
    return pd.DataFrame()


def append_row(path, row):
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
    row = df[df['member_id'] == session['member_id']]
    return row.iloc[0].to_dict() if not row.empty else None


# ═══════════════════════════════════════════════════════════
# PUBLIC LAYOUT (uses your existing style.css)
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
            <a href="{{ url_for('index') }}">Home</a>
            {% if session.member_id %}
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('polls_page') }}">Polls</a>
                <a href="{{ url_for('dues_page') }}">Dues</a>
                <a href="{{ url_for('contributions_page') }}">Contribute</a>
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
    {% block content %}{% endblock %}
</main>

<footer class="main-footer">
    <div class="footer-content">
        <p><strong>ODADEAƐ07</strong> — PRESEC 2007 Year Group</p>
        <p class="motto">"In Lumine Tuo Videbimus Lumen"</p>
        <p>© {{ year }} ODADEAƐ07</p>
    </div>
</footer>
</body>
</html>
"""


def page(content, **ctx):
    ctx.setdefault('year', datetime.now().year)
    ctx['content'] = content
    return render_template_string(PUBLIC_LAYOUT, **ctx)


# ═══════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ═══════════════════════════════════════════════════════════
@app.route('/')
def index():
    members = load_csv(MEMBERS_FILE)
    content = render_template_string("""
    <div class="hero-section">
      <div class="hero-content">
        <h1>Welcome Home, Odadeɛ</h1>
        <p class="hero-subtitle">PRESEC Class of 2007</p>
        <p class="hero-motto">"In Lumine Tuo Videbimus Lumen"</p>
        <div class="hero-stats">
          <div class="stat-card">
            <span class="stat-number">{{ member_count }}</span>
            <span class="stat-label">Members</span>
          </div>
        </div>
        <div class="hero-actions">
          <a href="{{ url_for('register') }}" class="btn btn-primary">Register</a>
          <a href="{{ url_for('login') }}" class="btn btn-secondary">Login</a>
        </div>
      </div>
    </div>
    """, member_count=len(members))
    return page(content)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email     = request.form.get('email', '').strip().lower()
        phone     = request.form.get('phone', '').strip()
        house     = request.form.get('house', '').strip()
        password  = request.form.get('password', '')
        if not (full_name and email and password):
            flash('Name, email and password are required.', 'danger')
            return redirect(url_for('register'))
        members = load_csv(MEMBERS_FILE)
        if not members.empty and email in members['email'].str.lower().values:
            flash('Email already registered.', 'danger')
            return redirect(url_for('login'))
        mid = f"MEM{int(time.time())}{random.randint(100,999)}"
        append_row(MEMBERS_FILE, {
            'member_id': mid, 'full_name': full_name, 'email': email,
            'phone': phone, 'house': house,
            'password_hash': generate_password_hash(password),
            'registered_at': datetime.now().isoformat(),
        })
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    content = render_template_string("""
    <div class="form-container">
      <h1>Register</h1>
      <p class="form-subtitle">Join the ODADEAƐ07 network</p>
      <form method="POST">
        <div class="form-group"><label>Full Name</label>
          <input name="full_name" required></div>
        <div class="form-group"><label>Email</label>
          <input type="email" name="email" required></div>
        <div class="form-group"><label>Phone</label>
          <input name="phone"></div>
        <div class="form-group"><label>House</label>
          <input name="house" placeholder="e.g. Akro, Labone"></div>
        <div class="form-group"><label>Password</label>
          <input type="password" name="password" required></div>
        <button class="btn btn-primary btn-full">Register</button>
      </form>
    </div>
    """)
    return page(content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        pwd   = request.form.get('password', '')
        members = load_csv(MEMBERS_FILE)
        if not members.empty:
            row = members[members['email'].str.lower() == email]
            if not row.empty and check_password_hash(row.iloc[0]['password_hash'], pwd):
                session['member_id'] = row.iloc[0]['member_id']
                session.permanent = True
                flash('Welcome back.', 'success')
                return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')

    content = render_template_string("""
    <div class="form-container">
      <h1>Login</h1>
      <form method="POST">
        <div class="form-group"><label>Email</label>
          <input type="email" name="email" required></div>
        <div class="form-group"><label>Password</label>
          <input type="password" name="password" required></div>
        <button class="btn btn-primary btn-full">Login</button>
      </form>
    </div>
    """)
    return page(content)


@app.route('/logout')
def logout():
    session.pop('member_id', None)
    flash('Logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@member_required
def dashboard():
    m = current_member()
    content = render_template_string("""
    <div class="dashboard-header">
      <div><h1>Welcome, {{ m.full_name }}</h1>
      <p>{{ m.email }}</p></div>
    </div>
    <div class="admin-actions">
      <a href="{{ url_for('polls_page') }}" class="btn btn-primary">🗳️ Polls</a>
      <a href="{{ url_for('dues_page') }}" class="btn btn-primary">📅 Dues</a>
      <a href="{{ url_for('contributions_page') }}" class="btn btn-primary">🎯 Contribute</a>
    </div>
    """, m=m)
    return page(content)


@app.route('/polls', methods=['GET', 'POST'])
@member_required
def polls_page():
    if request.method == 'POST':
        poll_id  = request.form.get('poll_id')
        option_id = request.form.get('option_id')
        if poll_id and option_id:
            votes = load_csv(VOTES_FILE)
            already = (not votes.empty and
                       ((votes['poll_id'] == poll_id) &
                        (votes['member_id'] == session['member_id'])).any())
            if already:
                flash('You already voted in this poll.', 'warning')
            else:
                m = current_member()
                append_row(VOTES_FILE, {
                    'vote_id': f"V{int(time.time())}{random.randint(100,999)}",
                    'poll_id': poll_id, 'option_id': option_id,
                    'member_id': session['member_id'],
                    'member_name': m['full_name'],
                    'voted_at': datetime.now().isoformat(),
                })
                flash('Vote recorded.', 'success')
        return redirect(url_for('polls_page'))

    polls = load_csv(POLLS_FILE)
    votes = load_csv(VOTES_FILE)
    my_votes = set(votes[votes['member_id'] == session['member_id']]['poll_id'].tolist()) if not votes.empty else set()

    poll_list = []
    if not polls.empty:
        for _, p in polls.iterrows():
            if str(p.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            try:
                opts = json.loads(p['options_json'])
            except Exception:
                opts = []
            poll_list.append({
                'id': p['poll_id'], 'title': p['title'],
                'description': p.get('description', ''),
                'options': opts, 'voted': p['poll_id'] in my_votes,
            })

    content = render_template_string("""
    <div class="reports-header"><div><h1>🗳️ Active Polls</h1></div></div>
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
          <button class="btn btn-primary">Vote</button>
        </form>
      {% endif %}
    </div>
    {% else %}<p class="empty-state">No active polls.</p>{% endfor %}
    """, polls=poll_list)
    return page(content)


@app.route('/dues', methods=['GET', 'POST'])
@member_required
def dues_page():
    if request.method == 'POST':
        dues_id = request.form.get('dues_id')
        amount  = float(request.form.get('amount', 0) or 0)
        method  = request.form.get('method', 'Mobile Money')
        if dues_id and amount > 0:
            m = current_member()
            append_row(DUES_FILE, {
                'payment_id': f"D{int(time.time())}{random.randint(100,999)}",
                'dues_id': dues_id,
                'member_id': session['member_id'],
                'member_name': m['full_name'],
                'amount': amount, 'method': method, 'note': '',
                'created_at': datetime.now().isoformat(),
            })
            flash('Dues payment recorded.', 'success')
        return redirect(url_for('dues_page'))

    plans = load_csv(DUES_CAMPAIGNS_FILE)
    dues  = load_csv(DUES_FILE)
    my_paid = set(dues[dues['member_id'] == session['member_id']]['dues_id'].tolist()) if not dues.empty else set()

    rows = []
    if not plans.empty:
        for _, d in plans.iterrows():
            if str(d.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            rows.append({
                'id': d['dues_id'], 'label': f"{d['month']} {d['year']}",
                'amount': float(d['amount']),
                'paid': d['dues_id'] in my_paid,
            })

    content = render_template_string("""
    <div class="reports-header"><div><h1>📅 Dues</h1></div></div>
    {% for d in dues_list %}
    <div class="poll-item">
      <h3>{{ d.label }} — GH₵{{ "%.2f"|format(d.amount) }}</h3>
      {% if d.paid %}
        <span class="voted-badge">✅ Paid</span>
      {% else %}
        <form method="POST">
          <input type="hidden" name="dues_id" value="{{ d.id }}">
          <div class="form-group"><label>Amount</label>
            <input type="number" step="0.01" name="amount"
                   value="{{ d.amount }}" required></div>
          <div class="form-group"><label>Method</label>
            <select name="method">
              <option>Mobile Money</option><option>Bank</option><option>Cash</option>
            </select></div>
          <button class="btn btn-primary">Pay</button>
        </form>
      {% endif %}
    </div>
    {% else %}<p class="empty-state">No dues periods open.</p>{% endfor %}
    """, dues_list=rows)
    return page(content)


@app.route('/contributions', methods=['GET', 'POST'])
@member_required
def contributions_page():
    if request.method == 'POST':
        cid    = request.form.get('campaign_id')
        amount = float(request.form.get('amount', 0) or 0)
        method = request.form.get('method', 'Mobile Money')
        if cid and amount > 0:
            m = current_member()
            append_row(CONTRIBUTIONS_FILE, {
                'contribution_id': f"C{int(time.time())}{random.randint(100,999)}",
                'campaign_id': cid,
                'member_id': session['member_id'],
                'member_name': m['full_name'],
                'amount': amount, 'method': method, 'note': '',
                'created_at': datetime.now().isoformat(),
            })
            flash('Contribution recorded. Thank you!', 'success')
        return redirect(url_for('contributions_page'))

    camps = load_csv(CAMPAIGNS_FILE)
    contribs = load_csv(CONTRIBUTIONS_FILE)
    rows = []
    if not camps.empty:
        for _, c in camps.iterrows():
            if str(c.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            raised = 0.0
            if not contribs.empty and 'campaign_id' in contribs.columns:
                sub = contribs[contribs['campaign_id'] == c['campaign_id']]
                raised = float(pd.to_numeric(sub['amount'], errors='coerce').fillna(0).sum())
            target = float(c.get('target_amount', 0))
            rows.append({
                'id': c['campaign_id'], 'title': c['title'],
                'description': c.get('description', ''),
                'raised': raised, 'target': target,
                'pct': min(raised/target*100, 100) if target else 0,
            })

    content = render_template_string("""
    <div class="reports-header"><div><h1>🎯 Contributions</h1></div></div>
    {% for c in camps %}
    <div class="poll-item">
      <h3>{{ c.title }}</h3>
      <p>{{ c.description }}</p>
      <div class="progress-track">
        <div class="progress-fill" style="width: {{ c.pct }}%"></div>
      </div>
      <p>GH₵{{ "%.2f"|format(c.raised) }} of GH₵{{ "%.2f"|format(c.target) }}</p>
      <form method="POST">
        <input type="hidden" name="campaign_id" value="{{ c.id }}">
        <div class="form-group"><label>Amount</label>
          <input type="number" step="0.01" name="amount" required></div>
        <div class="form-group"><label>Method</label>
          <select name="method">
            <option>Mobile Money</option><option>Bank</option><option>Cash</option>
          </select></div>
        <button class="btn btn-primary">Contribute</button>
      </form>
    </div>
    {% else %}<p class="empty-state">No active campaigns.</p>{% endfor %}
    """, camps=rows)
    return page(content)


# ═══════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════
@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'time': datetime.now().isoformat()})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
