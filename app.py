"""
app.py — ODADEAƐ07 Main Application (Secured, Supabase-aware, Password Reset)

Member name fields:
  • first_name   — given name
  • middle_name  — middle name
  • last_name    — family name

Date of birth:
  • dob_day      — 1 to 31
  • dob_month    — January…December
  • dob_year     — 4-digit year

Other profile fields:
  • title, emergency_contact, job_title, industry, phone, house

Diagnostics:
  • /health          — basic status
  • /debug-supabase  — per-table Supabase connectivity check (remove in production later)
"""

import os
import json
import time
import random
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import (Flask, render_template_string, request, session, redirect,
                   url_for, flash, send_file, jsonify)
from flask_wtf.csrf import CSRFProtect, CSRFError
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash

import supabase_client as sb
import password_reset as pr
import mailer

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

app.secret_key = os.environ.get(
    'SECRET_KEY',
    'dev-only-change-me-' + str(random.randint(100000, 999999))
)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    WTF_CSRF_TIME_LIMIT=None,
)

csrf = CSRFProtect(app)


# ═══════════════════════════════════════════════════════════
# ADMIN PANEL MOUNT
# ═══════════════════════════════════════════════════════════
from admin_routes import admin_bp  # noqa: E402
app.register_blueprint(admin_bp)


# ═══════════════════════════════════════════════════════════
# RATE LIMITERS
# ═══════════════════════════════════════════════════════════
_login_attempts = defaultdict(list)
_reset_attempts = defaultdict(list)
_WINDOW = timedelta(minutes=15)
_MAX    = 5
_RESET_WINDOW = timedelta(hours=1)
_RESET_MAX    = 3


def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _locked(store, ip, window, max_attempts):
    now = datetime.now()
    store[ip] = [t for t in store[ip] if now - t < window]
    return len(store[ip]) >= max_attempts


def _record(store, ip):
    store[ip].append(datetime.now())


def _clear(store, ip):
    store.pop(ip, None)


# ═══════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Security check failed. Please try again.', 'danger')
    return redirect(url_for('index'))


# ═══════════════════════════════════════════════════════════
# DATA HELPERS
# ═══════════════════════════════════════════════════════════
def load_csv(path):
    if os.path.exists(path):
        return pd.read_csv(path, dtype=str).fillna('')
    return pd.DataFrame()


def append_row(path, row):
    df = load_csv(path)
    new = pd.DataFrame([row])
    out = pd.concat([df, new], ignore_index=True) if not df.empty else new
    out.to_csv(path, index=False)


def load_table(table_name, csv_path):
    if sb.SUPABASE_ENABLED:
        rows = sb.fetch_all(table_name)
        if rows:
            return pd.DataFrame(rows).fillna('').astype(str)
        return pd.DataFrame()
    return load_csv(csv_path)


def insert_row(table_name, csv_path, row):
    if sb.SUPABASE_ENABLED:
        client = sb.get_client()
        if client is not None:
            try:
                client.table(table_name).insert(row).execute()
                return True
            except Exception as e:
                print(f'[Supabase insert failed for {table_name}]: {e}')
    append_row(csv_path, row)
    return True


T_MEMBERS        = 'members'
T_POLLS          = 'polls'
T_VOTES          = 'votes'
T_CONTRIBUTIONS  = 'contributions'
T_CAMPAIGNS      = 'contributions_campaigns'
T_DUES           = 'dues'
T_DUES_CAMPAIGNS = 'dues_campaigns'


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
    df = load_table(T_MEMBERS, MEMBERS_FILE)
    if df.empty:
        return None
    row = df[df['member_id'] == session['member_id']]
    return row.iloc[0].to_dict() if not row.empty else None


def safe_amount(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def sanitize(s, max_len=200):
    if s is None:
        return ''
    s = str(s).strip()
    s = s.replace('\r', '').replace('\n', '').replace('\x00', '')
    return s[:max_len]


def build_full_name(first, middle, last):
    """Compose 'First Middle Last' from parts."""
    parts = [str(first or '').strip(),
             str(middle or '').strip(),
             str(last or '').strip()]
    return ' '.join(p for p in parts if p)


def format_dob(day, month, year):
    """Compose '15 March 1985' from parts."""
    parts = [str(day or '').strip(),
             str(month or '').strip(),
             str(year or '').strip()]
    return ' '.join(p for p in parts if p)


MONTHS = ['January','February','March','April','May','June',
          'July','August','September','October','November','December']


# ═══════════════════════════════════════════════════════════
# PUBLIC LAYOUT
# ═══════════════════════════════════════════════════════════
PUBLIC_LAYOUT = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
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
                <a href="{{ url_for('members_directory') }}">Members</a>
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

<main class="main-content">{{ content|safe }}</main>

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
# HOME
# ═══════════════════════════════════════════════════════════
@app.route('/')
def index():
    members = load_table(T_MEMBERS, MEMBERS_FILE)
    polls   = load_table(T_POLLS, POLLS_FILE)
    camps   = load_table(T_CAMPAIGNS, CAMPAIGNS_FILE)

    content = render_template_string("""
    <div class="hero-section">
      <div class="hero-content">
        <h1>Welcome Home, Odadeɛ</h1>
        <p class="hero-subtitle">Presbyterian Boys' Secondary School</p>
        <p class="hero-motto">Class of 2007 — Ɔdadeɛ</p>
        <div class="hero-stats">
          <div class="stat-card">
            <span class="stat-number">{{ member_count }}</span>
            <span class="stat-label">Members</span>
          </div>
          <div class="stat-card">
            <span class="stat-number">{{ poll_count }}</span>
            <span class="stat-label">Polls</span>
          </div>
          <div class="stat-card">
            <span class="stat-number">{{ camp_count }}</span>
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
    """, member_count=len(members), poll_count=len(polls), camp_count=len(camps))
    return page(content)


# ═══════════════════════════════════════════════════════════
# REGISTER
# ═══════════════════════════════════════════════════════════
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        title             = sanitize(request.form.get('title', ''), 20)
        first_name        = sanitize(request.form.get('first_name', ''), 120)
        middle_name       = sanitize(request.form.get('middle_name', ''), 120)
        last_name         = sanitize(request.form.get('last_name', ''), 120)
        dob_day           = sanitize(request.form.get('dob_day', ''), 2)
        dob_month         = sanitize(request.form.get('dob_month', ''), 20)
        dob_year          = sanitize(request.form.get('dob_year', ''), 4)
        email             = sanitize(request.form.get('email', ''), 120).lower()
        phone             = sanitize(request.form.get('phone', ''), 40)
        house             = sanitize(request.form.get('house', ''), 60)
        emergency_contact = sanitize(request.form.get('emergency_contact', ''), 200)
        job_title         = sanitize(request.form.get('job_title', ''), 120)
        industry          = sanitize(request.form.get('industry', ''), 120)
        password          = request.form.get('password', '')
        confirm           = request.form.get('confirm', '')

        if not (first_name and last_name and email and password):
            flash('First name, last name, email and password are required.', 'danger')
            return redirect(url_for('register'))
        if '@' not in email or '.' not in email:
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(url_for('register'))
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if dob_day:
            try:
                d = int(dob_day)
                if d < 1 or d > 31:
                    raise ValueError
            except ValueError:
                flash('Date of birth day must be between 1 and 31.', 'danger')
                return redirect(url_for('register'))
        if dob_year:
            try:
                y = int(dob_year)
                if y < 1900 or y > datetime.now().year:
                    raise ValueError
            except ValueError:
                flash('Please enter a valid birth year.', 'danger')
                return redirect(url_for('register'))

        members = load_table(T_MEMBERS, MEMBERS_FILE)
        if not members.empty and email in members['email'].str.lower().values:
            flash('This email is already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        full_name = build_full_name(first_name, middle_name, last_name)
        mid = f"MEM{int(time.time())}{random.randint(100,999)}"

        insert_row(T_MEMBERS, MEMBERS_FILE, {
            'member_id':         mid,
            'title':             title,
            'first_name':        first_name,
            'middle_name':       middle_name,
            'last_name':         last_name,
            'full_name':         full_name,
            'dob_day':           dob_day,
            'dob_month':         dob_month,
            'dob_year':          dob_year,
            'email':             email,
            'phone':             phone,
            'house':             house,
            'emergency_contact': emergency_contact,
            'job_title':         job_title,
            'industry':          industry,
            'password_hash':     generate_password_hash(password),
            'registered_at':     datetime.now().isoformat(),
        })
        flash(f'Welcome, {full_name}! Please log in.', 'success')
        return redirect(url_for('login'))

    content = render_template_string("""
    <div class="form-container">
      <h1>Join ODADEAƐ07</h1>
      <p class="form-subtitle">Register as a member of the 2007 Year Group</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <h3 style="margin-bottom:0.5rem;color:var(--presec-blue);">Name</h3>
        <div class="form-row">
          <div class="form-group"><label>Title</label>
            <select name="title">
              <option value="">—</option>
              <option>Mr</option><option>Mrs</option><option>Miss</option>
              <option>Dr</option><option>Rev</option><option>Prof</option>
              <option>Hon</option><option>Nana</option><option>Nii</option>
            </select></div>
          <div class="form-group"><label>House</label>
            <input name="house" placeholder="e.g. Akro, Labone" maxlength="60"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>First Name *</label>
            <input name="first_name" required maxlength="120"></div>
          <div class="form-group"><label>Middle Name</label>
            <input name="middle_name" maxlength="120"></div>
        </div>
        <div class="form-group"><label>Last Name *</label>
          <input name="last_name" required maxlength="120"></div>

        <h3 style="margin:1rem 0 0.5rem;color:var(--presec-blue);">Date of Birth</h3>
        <div class="form-row" style="grid-template-columns: 1fr 2fr 1fr;">
          <div class="form-group"><label>Day</label>
            <input name="dob_day" type="number" min="1" max="31" placeholder="15"></div>
          <div class="form-group"><label>Month</label>
            <select name="dob_month">
              <option value="">—</option>
              {% for m in months %}<option>{{ m }}</option>{% endfor %}
            </select></div>
          <div class="form-group"><label>Year</label>
            <input name="dob_year" type="number" min="1900" max="2026" placeholder="1985"></div>
        </div>

        <h3 style="margin:1rem 0 0.5rem;color:var(--presec-blue);">Contact</h3>
        <div class="form-group"><label>Email *</label>
          <input type="email" name="email" required maxlength="120"></div>
        <div class="form-row">
          <div class="form-group"><label>Phone</label>
            <input name="phone" placeholder="+233 ..." maxlength="40"></div>
          <div class="form-group"><label>Emergency Contact</label>
            <input name="emergency_contact" placeholder="Name + phone" maxlength="200"></div>
        </div>

        <h3 style="margin:1rem 0 0.5rem;color:var(--presec-blue);">Professional</h3>
        <div class="form-row">
          <div class="form-group"><label>Job Title</label>
            <input name="job_title" placeholder="e.g. Accountant" maxlength="120"></div>
          <div class="form-group"><label>Industry</label>
            <input name="industry" placeholder="e.g. Finance, Tech" maxlength="120"></div>
        </div>

        <h3 style="margin:1rem 0 0.5rem;color:var(--presec-blue);">Account</h3>
        <div class="form-row">
          <div class="form-group"><label>Password * (min 8 chars)</label>
            <input type="password" name="password" required minlength="8"></div>
          <div class="form-group"><label>Confirm Password *</label>
            <input type="password" name="confirm" required minlength="8"></div>
        </div>

        <button class="btn btn-primary btn-full">Create Account</button>
      </form>
      <p class="form-footer">Already registered?
        <a href="{{ url_for('login') }}">Log in</a></p>
    </div>
    """, months=MONTHS)
    return page(content)


# ═══════════════════════════════════════════════════════════
# LOGIN
# ═══════════════════════════════════════════════════════════
@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = _client_ip()
    if request.method == 'POST':
        if _locked(_login_attempts, ip, _WINDOW, _MAX):
            flash('Too many failed attempts. Try again in 15 minutes.', 'danger')
            return redirect(url_for('login'))

        email = sanitize(request.form.get('email', ''), 120).lower()
        pwd   = request.form.get('password', '')

        members = load_table(T_MEMBERS, MEMBERS_FILE)
        ok = False
        row = None
        if not members.empty:
            sub = members[members['email'].str.lower() == email]
            if not sub.empty:
                row = sub
                stored = sub.iloc[0].get('password_hash', '')
                try:
                    ok = check_password_hash(stored, pwd)
                except Exception:
                    ok = False

        if ok and row is not None:
            _clear(_login_attempts, ip)
            session['member_id'] = row.iloc[0]['member_id']
            session.permanent = True
            r = row.iloc[0]
            display = (r.get('first_name') or r.get('full_name') or 'Odadeɛ')
            flash(f"Welcome back, {display}!", 'success')
            return redirect(url_for('dashboard'))

        _record(_login_attempts, ip)
        remaining = _MAX - len(_login_attempts[ip])
        if remaining > 0:
            flash(f'Invalid email or password. {remaining} attempts left.', 'danger')
        else:
            flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')

    content = render_template_string("""
    <div class="form-container">
      <h1>Login</h1>
      <p class="form-subtitle">Welcome back, Odadeɛ</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group"><label>Email</label>
          <input type="email" name="email" required autofocus maxlength="120"></div>
        <div class="form-group"><label>Password</label>
          <input type="password" name="password" required></div>
        <button class="btn btn-primary btn-full">Login</button>
      </form>
      <p class="form-footer">
        <a href="{{ url_for('forgot_password') }}">Forgot password?</a> •
        New here? <a href="{{ url_for('register') }}">Register</a>
      </p>
    </div>
    """)
    return page(content)


@app.route('/logout')
def logout():
    session.pop('member_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# ═══════════════════════════════════════════════════════════
# FORGOT PASSWORD
# ═══════════════════════════════════════════════════════════
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    ip = _client_ip()
    if request.method == 'POST':
        if _locked(_reset_attempts, ip, _RESET_WINDOW, _RESET_MAX):
            flash('Too many reset requests. Please try again later.', 'danger')
            return redirect(url_for('forgot_password'))

        email = sanitize(request.form.get('email', ''), 120).lower()
        success_msg = ('If that email is registered, a reset link has been sent. '
                       'Check your inbox and spam folder.')

        if not email or '@' not in email:
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('forgot_password'))

        members = load_table(T_MEMBERS, MEMBERS_FILE)
        member = None
        if not members.empty:
            sub = members[members['email'].str.lower() == email]
            if not sub.empty:
                member = sub.iloc[0].to_dict()

        if member:
            token = pr.create_reset_token(member['member_id'], email)
            base = request.url_root.rstrip('/')
            reset_url = f'{base}/reset-password?token={token}'
            display_name = (member.get('first_name') or
                            member.get('full_name') or 'Odadeɛ')
            ok, err = mailer.send_password_reset(email, display_name, reset_url)
            if not ok:
                print(f'[forgot-password] Email failed for {email}: {err}')
                print(f'[forgot-password] Manual link: {reset_url}')

        _record(_reset_attempts, ip)
        flash(success_msg, 'info')
        return redirect(url_for('login'))

    content = render_template_string("""
    <div class="form-container">
      <h1>Forgot your password?</h1>
      <p class="form-subtitle">Enter your email and we'll send a reset link</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group"><label>Email</label>
          <input type="email" name="email" required autofocus maxlength="120"></div>
        <button class="btn btn-primary btn-full">Send reset link</button>
      </form>
      <p class="form-footer">
        Remembered it? <a href="{{ url_for('login') }}">Back to login</a>
      </p>
    </div>
    """)
    return page(content)


# ═══════════════════════════════════════════════════════════
# RESET PASSWORD
# ═══════════════════════════════════════════════════════════
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token', '') or request.form.get('token', '')
    row = pr.verify_token(token)
    if not row:
        content = render_template_string("""
        <div class="form-container" style="text-align:center;">
          <h1>Invalid or expired link</h1>
          <p class="form-subtitle">
            This reset link has expired or was already used.
          </p>
          <a href="{{ url_for('forgot_password') }}" class="btn btn-primary">
            Request a new link
          </a>
        </div>
        """)
        return page(content)

    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirm      = request.form.get('confirm', '')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(url_for('reset_password', token=token))
        if new_password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        ok, msg = pr.consume_token(token, new_password)
        if ok:
            flash(msg, 'success')
            return redirect(url_for('login'))
        flash(msg, 'danger')
        return redirect(url_for('forgot_password'))

    content = render_template_string("""
    <div class="form-container">
      <h1>Choose a new password</h1>
      <p class="form-subtitle">Your data stays exactly the same</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="token" value="{{ token }}">
        <div class="form-group"><label>New password (min 8 chars)</label>
          <input type="password" name="password" required minlength="8" autofocus></div>
        <div class="form-group"><label>Confirm new password</label>
          <input type="password" name="confirm" required minlength="8"></div>
        <button class="btn btn-primary btn-full">Update password</button>
      </form>
    </div>
    """, token=token)
    return page(content)


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

    votes    = load_table(T_VOTES, VOTES_FILE)
    dues     = load_table(T_DUES, DUES_FILE)
    contribs = load_table(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE)
    members  = load_table(T_MEMBERS, MEMBERS_FILE)

    my_votes   = len(votes[votes['member_id'] == m['member_id']]) if not votes.empty else 0
    my_dues    = safe_amount(pd.to_numeric(dues[dues['member_id'] == m['member_id']]['amount'], errors='coerce').fillna(0).sum()) if not dues.empty else 0
    my_contrib = safe_amount(pd.to_numeric(contribs[contribs['member_id'] == m['member_id']]['amount'], errors='coerce').fillna(0).sum()) if not contribs.empty else 0

    full_display = ' '.join(filter(None, [
        m.get('title',''), m.get('first_name',''),
        m.get('middle_name',''), m.get('last_name','')
    ])) or m.get('full_name','')

    dob_display = format_dob(m.get('dob_day',''), m.get('dob_month',''), m.get('dob_year',''))

    content = render_template_string("""
    <div class="dashboard-header">
      <div>
        <h1>Akwaaba, {{ display_name }}</h1>
        <p>{{ m.email }}{% if m.house %} • {{ m.house }} House{% endif %}</p>
      </div>
      <div class="member-info">
        <div class="member-photo-placeholder">
          {{ (m.get('first_name') or m.get('full_name','?'))[0]|upper }}
        </div>
      </div>
    </div>

    <div class="dash-stats-bar">
      <div class="dash-stat">
        <div class="dash-stat-icon">🗳️</div>
        <div class="dash-stat-text">
          <span class="dash-stat-value">{{ my_votes }}</span>
          <span class="dash-stat-label">Votes Cast</span>
        </div>
      </div>
      <div class="dash-stat">
        <div class="dash-stat-icon">📅</div>
        <div class="dash-stat-text">
          <span class="dash-stat-value">GH₵{{ "%.2f"|format(my_dues) }}</span>
          <span class="dash-stat-label">Dues Paid</span>
        </div>
      </div>
      <div class="dash-stat">
        <div class="dash-stat-icon">🎯</div>
        <div class="dash-stat-text">
          <span class="dash-stat-value">GH₵{{ "%.2f"|format(my_contrib) }}</span>
          <span class="dash-stat-label">Contributed</span>
        </div>
      </div>
      <div class="dash-stat">
        <div class="dash-stat-icon">👥</div>
        <div class="dash-stat-text">
          <span class="dash-stat-value">{{ member_count }}</span>
          <span class="dash-stat-label">Total Members</span>
        </div>
      </div>
    </div>

    <div class="report-section">
      <h2>📇 My Profile</h2>
      <div class="table-wrapper">
        <table class="report-table full-width">
          <tbody>
            <tr><th>Title</th><td>{{ m.get('title','') or '—' }}</td></tr>
            <tr><th>First Name</th><td>{{ m.get('first_name','') or '—' }}</td></tr>
            <tr><th>Middle Name</th><td>{{ m.get('middle_name','') or '—' }}</td></tr>
            <tr><th>Last Name</th><td>{{ m.get('last_name','') or '—' }}</td></tr>
            <tr><th>Date of Birth</th><td>{{ dob }}</td></tr>
            <tr><th>Email</th><td>{{ m.email }}</td></tr>
            <tr><th>Phone</th><td>{{ m.get('phone','') or '—' }}</td></tr>
            <tr><th>House</th><td>{{ m.get('house','') or '—' }}</td></tr>
            <tr><th>Emergency Contact</th><td>{{ m.get('emergency_contact','') or '—' }}</td></tr>
            <tr><th>Job Title</th><td>{{ m.get('job_title','') or '—' }}</td></tr>
            <tr><th>Industry</th><td>{{ m.get('industry','') or '—' }}</td></tr>
          </tbody>
        </table>
      </div>
      <p style="margin-top:1rem;color:var(--gray-500);font-size:0.9rem;">
        To update your profile, contact the admin.
      </p>
    </div>

    <div class="admin-actions">
      <a href="{{ url_for('polls_page') }}"          class="btn btn-primary">🗳️ Vote in Polls</a>
      <a href="{{ url_for('dues_page') }}"           class="btn btn-primary">📅 Pay Dues</a>
      <a href="{{ url_for('contributions_page') }}"  class="btn btn-primary">🎯 Contribute</a>
      <a href="{{ url_for('members_directory') }}"   class="btn btn-secondary">👥 Members</a>
    </div>
    """, m=m, display_name=full_display, dob=dob_display or '—',
         my_votes=my_votes, my_dues=my_dues, my_contrib=my_contrib,
         member_count=len(members))
    return page(content)


# ═══════════════════════════════════════════════════════════
# MEMBERS DIRECTORY
# ═══════════════════════════════════════════════════════════
@app.route('/members')
@member_required
def members_directory():
    df = load_table(T_MEMBERS, MEMBERS_FILE)
    if not df.empty and 'password_hash' in df.columns:
        df = df.drop(columns=['password_hash'])
    members = df.to_dict('records') if not df.empty else []

    houses = {}
    for m in members:
        h = (m.get('house') or 'Not Specified').strip() or 'Not Specified'
        houses.setdefault(h, []).append(m)

    content = render_template_string("""
    <div class="reports-header">
      <div>
        <h1>👥 Membership Directory</h1>
        <p class="subtitle">{{ members|length }} registered Odadeɛ</p>
      </div>
      <div class="report-actions">
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    {% for house, list in houses.items() %}
    <div class="report-section">
      <h2>🏠 {{ house }} House ({{ list|length }})</h2>
      <div class="table-wrapper">
        <table class="report-table full-width">
          <thead>
            <tr>
              <th>Name</th><th>Email</th><th>Phone</th>
              <th>Job Title</th><th>Industry</th><th>Joined</th>
            </tr>
          </thead>
          <tbody>
            {% for m in list %}
            <tr>
              <td><strong>{{ m.get('title','') }} {{ m.get('first_name') or m.get('full_name','') }} {{ m.get('middle_name','') }} {{ m.get('last_name','') }}</strong></td>
              <td>{{ m.email }}</td>
              <td>{{ m.phone or '—' }}</td>
              <td>{{ m.get('job_title','') or '—' }}</td>
              <td>{{ m.get('industry','') or '—' }}</td>
              <td>{{ m.registered_at[:10] if m.registered_at else '—' }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
    {% else %}
    <p class="empty-state">No members yet.</p>
    {% endfor %}
    """, members=members, houses=houses)
    return page(content)


# ═══════════════════════════════════════════════════════════
# POLLS
# ═══════════════════════════════════════════════════════════
@app.route('/polls', methods=['GET', 'POST'])
@member_required
def polls_page():
    if request.method == 'POST':
        poll_id   = request.form.get('poll_id')
        option_id = request.form.get('option_id')
        if not (poll_id and option_id):
            flash('Please select an option.', 'warning')
            return redirect(url_for('polls_page'))

        votes = load_table(T_VOTES, VOTES_FILE)
        already = (not votes.empty and
                   ((votes['poll_id'] == poll_id) &
                    (votes['member_id'] == session['member_id'])).any())
        if already:
            flash('You already voted in this poll.', 'warning')
            return redirect(url_for('polls_page'))

        m = current_member()
        insert_row(T_VOTES, VOTES_FILE, {
            'vote_id':     f"V{int(time.time())}{random.randint(100,999)}",
            'poll_id':     poll_id,
            'option_id':   option_id,
            'member_id':   session['member_id'],
            'member_name': m['full_name'] if m else '',
            'voted_at':    datetime.now().isoformat(),
        })
        flash('✅ Vote recorded. Thank you!', 'success')
        return redirect(url_for('polls_page'))

    polls = load_table(T_POLLS, POLLS_FILE)
    votes = load_table(T_VOTES, VOTES_FILE)
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
    <div class="reports-header">
      <div><h1>🗳️ Active Polls</h1>
      <p class="subtitle">{{ polls|length }} open poll(s)</p></div>
      <div class="report-actions">
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    {% for p in polls %}
    <div class="poll-item">
      <h3>{{ p.title }}</h3>
      {% if p.description %}<p>{{ p.description }}</p>{% endif %}
      {% if p.voted %}
        <span class="voted-badge">✅ You've voted</span>
      {% else %}
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
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
    <p class="empty-state">No active polls right now.</p>
    {% endfor %}
    """, polls=poll_list)
    return page(content)


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
        method = sanitize(request.form.get('method', 'Mobile Money'), 40)

        if dues_id and amount > 0:
            m = current_member()
            insert_row(T_DUES, DUES_FILE, {
                'payment_id':  f"D{int(time.time())}{random.randint(100,999)}",
                'dues_id':     dues_id,
                'member_id':   session['member_id'],
                'member_name': m['full_name'] if m else '',
                'amount':      amount,
                'method':      method,
                'note':        '',
                'created_at':  datetime.now().isoformat(),
            })
            flash(f'✅ Dues payment of GH₵{amount:.2f} recorded.', 'success')
        else:
            flash('Please enter a valid amount.', 'danger')
        return redirect(url_for('dues_page'))

    plans = load_table(T_DUES_CAMPAIGNS, DUES_CAMPAIGNS_FILE)
    dues  = load_table(T_DUES, DUES_FILE)
    my_paid = set(dues[dues['member_id'] == session['member_id']]['dues_id'].tolist()) if not dues.empty else set()

    rows = []
    if not plans.empty:
        for _, d in plans.iterrows():
            if str(d.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            rows.append({
                'id': d['dues_id'],
                'label': f"{d.get('month','')} {d.get('year','')}",
                'amount': safe_amount(d.get('amount', 0)),
                'paid': d['dues_id'] in my_paid,
            })

    content = render_template_string("""
    <div class="reports-header">
      <div><h1>📅 Monthly Dues</h1>
      <p class="subtitle">Pay your dues for open periods</p></div>
      <div class="report-actions">
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    {% for d in dues_list %}
    <div class="poll-item">
      <h3>{{ d.label }} — GH₵{{ "%.2f"|format(d.amount) }}</h3>
      {% if d.paid %}
        <span class="voted-badge">✅ Paid</span>
      {% else %}
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="hidden" name="dues_id" value="{{ d.id }}">
          <div class="form-row">
            <div class="form-group"><label>Amount (GH₵)</label>
              <input type="number" step="0.01" name="amount"
                     value="{{ "%.2f"|format(d.amount) }}" required></div>
            <div class="form-group"><label>Method</label>
              <select name="method">
                <option>Mobile Money</option>
                <option>Bank Transfer</option>
                <option>Cash</option>
              </select></div>
          </div>
          <button class="btn btn-primary">Pay Dues</button>
        </form>
      {% endif %}
    </div>
    {% else %}
    <p class="empty-state">No dues periods are open right now.</p>
    {% endfor %}
    """, dues_list=rows)
    return page(content)


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
        method = sanitize(request.form.get('method', 'Mobile Money'), 40)

        if cid and amount > 0:
            m = current_member()
            insert_row(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE, {
                'contribution_id': f"C{int(time.time())}{random.randint(100,999)}",
                'campaign_id':     cid,
                'member_id':       session['member_id'],
                'member_name':     m['full_name'] if m else '',
                'amount':          amount,
                'method':          method,
                'note':            '',
                'created_at':      datetime.now().isoformat(),
            })
            flash(f'✅ Contribution of GH₵{amount:.2f} recorded. Thank you!', 'success')
        else:
            flash('Please enter a valid amount.', 'danger')
        return redirect(url_for('contributions_page'))

    camps    = load_table(T_CAMPAIGNS, CAMPAIGNS_FILE)
    contribs = load_table(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE)
    rows = []
    if not camps.empty:
        for _, c in camps.iterrows():
            if str(c.get('active', True)).lower() not in ['true', '1', 'yes']:
                continue
            raised = 0.0
            if not contribs.empty and 'campaign_id' in contribs.columns:
                sub = contribs[contribs['campaign_id'] == c['campaign_id']]
                raised = safe_amount(pd.to_numeric(sub['amount'], errors='coerce').fillna(0).sum())
            target = safe_amount(c.get('target_amount', 0))
            rows.append({
                'id': c['campaign_id'], 'title': c['title'],
                'description': c.get('description', ''),
                'raised': raised, 'target': target,
                'pct': min(raised/target*100, 100) if target else 0,
            })

    content = render_template_string("""
    <div class="reports-header">
      <div><h1>🎯 Contributions</h1>
      <p class="subtitle">Support active campaigns</p></div>
      <div class="report-actions">
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    {% for c in camps %}
    <div class="poll-item">
      <h3>{{ c.title }}</h3>
      {% if c.description %}<p>{{ c.description }}</p>{% endif %}
      <div class="progress-track">
        <div class="progress-fill {% if c.pct >= 100 %}full{% endif %}"
             style="width: {{ c.pct }}%"></div>
      </div>
      <p style="margin-top:0.5rem;">
        <strong>GH₵{{ "%.2f"|format(c.raised) }}</strong>
        raised of GH₵{{ "%.2f"|format(c.target) }}
      </p>
      <form method="POST" style="margin-top:1rem;">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="campaign_id" value="{{ c.id }}">
        <div class="form-row">
          <div class="form-group"><label>Amount (GH₵)</label>
            <input type="number" step="0.01" name="amount" required></div>
          <div class="form-group"><label>Method</label>
            <select name="method">
              <option>Mobile Money</option>
              <option>Bank Transfer</option>
              <option>Cash</option>
            </select></div>
        </div>
        <button class="btn btn-primary">Contribute</button>
      </form>
    </div>
    {% else %}
    <p class="empty-state">No active campaigns right now.</p>
    {% endfor %}
    """, camps=rows)
    return page(content)


# ═══════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'supabase_enabled': sb.SUPABASE_ENABLED,
        'email_enabled': mailer.EMAIL_ENABLED,
        'time': datetime.now().isoformat()
    })


# ═══════════════════════════════════════════════════════════
# DEBUG — Supabase per-table check (temporary, remove later)
# ═══════════════════════════════════════════════════════════
@app.route('/debug-supabase')
def debug_supabase():
    """
    Diagnostic endpoint. For each Supabase table, it tries a
    single-row read and reports the exact error, if any.
    Remove this route before going to production long-term.
    """
    result = {
        'supabase_enabled': sb.SUPABASE_ENABLED,
        'supabase_url_set': bool(os.environ.get('SUPABASE_URL')),
        'supabase_key_set': bool(os.environ.get('SUPABASE_KEY')),
        'supabase_url_first_chars': (os.environ.get('SUPABASE_URL') or '')[:30],
        'supabase_key_first_chars': (os.environ.get('SUPABASE_KEY') or '')[:20],
        'client_initialized': False,
        'client_error': None,
        'tables': {}
    }

    try:
        client = sb.get_client()
    except Exception as e:
        result['client_error'] = str(e)
        client = None

    result['client_initialized'] = client is not None

    if client is None:
        return jsonify(result)

    for table in ['members', 'polls', 'votes', 'dues',
                  'dues_campaigns', 'contributions',
                  'contributions_campaigns', 'password_resets']:
        try:
            resp = client.table(table).select('*').limit(1).execute()
            rows = resp.data or []
            result['tables'][table] = {
                'ok': True,
                'sample_row_count': len(rows),
                'sample_keys': list(rows[0].keys()) if rows else []
            }
        except Exception as e:
            result['tables'][table] = {
                'ok': False,
                'error': str(e),
                'error_type': type(e).__name__
            }

    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)