"""
app.py — ODADEAƐ07 Main Application (Secured, Supabase, 2FA, profile editing)

New in this version:
  • Members can edit their own profile
  • Members can change their own password
  • Members can opt into 2FA (TOTP)
  • Login history per member
  • Poll scheduling (open_at / close_at) and anonymity
  • Persistent rate limiting (survives redeploys)
  • Session-expiry countdown in the header
"""

import os
import json
import time
import random
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template_string, request, session, redirect,
                   url_for, flash, jsonify, g)
from flask_wtf.csrf import CSRFProtect, CSRFError
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash

import supabase_client as sb
import password_reset as pr
import mailer
import two_factor as tf
from chart_helpers import bar_chart, line_chart, CHART_JS_CDN

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
# PERSISTENT RATE LIMITING
# ═══════════════════════════════════════════════════════════
_WINDOW = timedelta(minutes=15)
_MAX    = 5
_RESET_WINDOW = timedelta(hours=1)
_RESET_MAX    = 3


def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _rate_check(prefix, ip, window, max_attempts):
    key = f'{prefix}:{ip}'
    attempts = sb.rate_limit_get(key)
    now = datetime.now()
    cutoff = now - window
    attempts = [t for t in attempts if _parse_iso(t) and _parse_iso(t) > cutoff]
    locked = len(attempts) >= max_attempts
    return locked, attempts, key


def _rate_record(key, attempts):
    attempts = attempts + [datetime.now().isoformat()]
    sb.rate_limit_set(key, attempts)


def _rate_clear(prefix, ip):
    key = f'{prefix}:{ip}'
    sb.rate_limit_set(key, [])


def _parse_iso(s):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


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
    parts = [str(first or '').strip(),
             str(middle or '').strip(),
             str(last or '').strip()]
    return ' '.join(p for p in parts if p)


def format_dob(day, month, year):
    parts = [str(day or '').strip(),
             str(month or '').strip(),
             str(year or '').strip()]
    return ' '.join(p for p in parts if p)


def poll_is_open(p):
    """Check whether a poll is open right now, based on schedule."""
    now = datetime.now()
    active = str(p.get('active', 'True')).lower() in ['true', '1', 'yes']
    if not active:
        return False
    try:
        open_at = p.get('open_at', '') or ''
        if open_at:
            t = datetime.fromisoformat(open_at)
            if now < t:
                return False
    except Exception:
        pass
    try:
        close_at = p.get('close_at', '') or ''
        if close_at:
            t = datetime.fromisoformat(close_at)
            if now > t:
                return False
    except Exception:
        pass
    return True


MONTHS = ['January','February','March','April','May','June',
          'July','August','September','October','November','December']


# ═══════════════════════════════════════════════════════════
# PUBLIC LAYOUT (with session countdown)
# ═══════════════════════════════════════════════════════════
PUBLIC_LAYOUT = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>ODADEAƐ07 — PRESEC 2007 Year Group</title>
    <link rel="icon" href="{{ url_for('static', filename='images/presec-badge.png') }}">
    <link rel="manifest" href="{{ url_for('static', filename='manifest.json') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    {{ chartjs|safe }}
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
                <a href="{{ url_for('profile_page') }}">My Profile</a>
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
    {% if session.member_id %}
    <div id="session-banner" style="display:none;background:#fff8e1;color:#7a5800;
        padding:0.5rem 1rem;text-align:center;font-size:0.85rem;font-weight:600;
        border-bottom:1px solid #ffe0a3;">
      Your session ends in <span id="session-countdown">--:--</span>.
      <a href="{{ url_for('login') }}" style="color:#7a5800;text-decoration:underline;">Log in again</a>
      to keep it active.
    </div>
    {% endif %}
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

<script>
// Register a service worker for basic offline caching
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function() {
    navigator.serviceWorker.register('/static/sw.js').catch(function(){});
  });
}
// Session countdown
(function() {
  var banner = document.getElementById('session-banner');
  if (!banner) return;
  var expiresAt = {{ session_expires_ms|default(0) }};
  if (!expiresAt) return;
  function tick() {
    var left = expiresAt - Date.now();
    if (left <= 0) { window.location.href = '{{ url_for('login') }}'; return; }
    if (left < 5 * 60 * 1000) banner.style.display = 'block';
    var m = Math.floor(left / 60000);
    var s = Math.floor((left % 60000) / 1000);
    document.getElementById('session-countdown').textContent =
      m + ':' + (s < 10 ? '0' : '') + s;
  }
  setInterval(tick, 1000); tick();
})();
</script>
</body>
</html>
"""


def page(content, **ctx):
    ctx.setdefault('year', datetime.now().year)
    ctx.setdefault('chartjs', CHART_JS_CDN)
    if session.get('member_id'):
        ctx.setdefault('session_expires_ms', int((time.time() + 7 * 24 * 3600) * 1000))
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
        first_name        = sanitize(request.form.get('first_name', ''), 120)
        middle_name       = sanitize(request.form.get('middle_name', ''), 120)
        last_name         = sanitize(request.form.get('last_name', ''), 120)
        email             = sanitize(request.form.get('email', ''), 120).lower()
        phone             = sanitize(request.form.get('phone', ''), 40)
        house             = sanitize(request.form.get('house', ''), 60)
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

        members = load_table(T_MEMBERS, MEMBERS_FILE)
        if not members.empty and email in members['email'].str.lower().values:
            flash('This email is already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        full_name = build_full_name(first_name, middle_name, last_name)
        mid = f"MEM{int(time.time())}{random.randint(100,999)}"

        insert_row(T_MEMBERS, MEMBERS_FILE, {
            'member_id':         mid,
            'title':             '',
            'first_name':        first_name,
            'middle_name':       middle_name,
            'last_name':         last_name,
            'full_name':         full_name,
            'dob_day':           '',
            'dob_month':         '',
            'dob_year':          '',
            'email':             email,
            'phone':             phone,
            'house':             house,
            'emergency_contact': '',
            'job_title':         '',
            'industry':          '',
            'password_hash':     generate_password_hash(password),
            'registered_at':     datetime.now().isoformat(),
            'status':            'active',
            'role':              'member',
            'totp_secret':       '',
            'totp_enabled':      'False',
        })
        flash(f'Welcome, {full_name}! Please log in.', 'success')
        return redirect(url_for('login'))

    content = render_template_string("""
    <div class="form-container">
      <h1>Join ODADEAƐ07</h1>
      <p class="form-subtitle">Register as a member of the 2007 Year Group</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-row">
          <div class="form-group"><label>First Name *</label>
            <input name="first_name" required maxlength="120"></div>
          <div class="form-group"><label>Middle Name</label>
            <input name="middle_name" maxlength="120"></div>
        </div>
        <div class="form-group"><label>Last Name *</label>
          <input name="last_name" required maxlength="120"></div>
        <div class="form-group"><label>Email *</label>
          <input type="email" name="email" required maxlength="120"></div>
        <div class="form-row">
          <div class="form-group"><label>Phone</label>
            <input name="phone" maxlength="40"></div>
          <div class="form-group"><label>House</label>
            <input name="house" maxlength="60"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Password * (min 8)</label>
            <input type="password" name="password" required minlength="8"></div>
          <div class="form-group"><label>Confirm *</label>
            <input type="password" name="confirm" required minlength="8"></div>
        </div>
        <button class="btn btn-primary btn-full">Create Account</button>
      </form>
      <p class="form-footer">Already registered?
        <a href="{{ url_for('login') }}">Log in</a></p>
    </div>
    """)
    return page(content)


# ═══════════════════════════════════════════════════════════
# LOGIN (with 2FA + history + persistent rate limit)
# ═══════════════════════════════════════════════════════════
@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = _client_ip()
    if request.method == 'POST':
        locked, attempts, key = _rate_check('login', ip, _WINDOW, _MAX)
        if locked:
            flash('Too many failed attempts. Try again in 15 minutes.', 'danger')
            return redirect(url_for('login'))

        email = sanitize(request.form.get('email', ''), 120).lower()
        pwd   = request.form.get('password', '')

        members = load_table(T_MEMBERS, MEMBERS_FILE)
        row = None
        ok = False
        if not members.empty:
            sub = members[members['email'].str.lower() == email]
            if not sub.empty:
                row = sub.iloc[0].to_dict()
                if str(row.get('status', 'active')).lower() == 'suspended':
                    flash('This account has been suspended. Contact the admin.', 'danger')
                    return redirect(url_for('login'))
                try:
                    ok = check_password_hash(row.get('password_hash', ''), pwd)
                except Exception:
                    ok = False

        if ok and row:
            # Check 2FA
            if str(row.get('totp_enabled', 'False')).lower() == 'true':
                session['pending_2fa_member_id'] = row['member_id']
                return redirect(url_for('login_2fa'))

            _rate_clear('login', ip)
            session['member_id'] = row['member_id']
            session.permanent = True
            sb.log_login('member', row['member_id'], ip,
                         request.headers.get('User-Agent', ''), True)
            flash(f"Welcome back, {row.get('first_name') or row.get('full_name')}!", 'success')
            return redirect(url_for('dashboard'))

        _rate_record(key, attempts)
        sb.log_login('member', None, ip,
                     request.headers.get('User-Agent', ''), False)
        remaining = _MAX - (len(attempts) + 1)
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
          <input type="email" name="email" required autofocus></div>
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


@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    mid = session.get('pending_2fa_member_id')
    if not mid:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = sanitize(request.form.get('code', ''), 6)
        row = sb.fetch_one('members', 'member_id', mid)
        if row and tf.verify(row.get('totp_secret', ''), code):
            session.pop('pending_2fa_member_id', None)
            session['member_id'] = mid
            session.permanent = True
            sb.log_login('member', mid, _client_ip(),
                         request.headers.get('User-Agent', ''), True)
            flash('Welcome back.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid code. Try again.', 'danger')

    content = render_template_string("""
    <div class="form-container">
      <h1>Two-factor authentication</h1>
      <p class="form-subtitle">Enter the 6-digit code from your authenticator app</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group"><label>Code</label>
          <input name="code" required autofocus maxlength="6" inputmode="numeric"></div>
        <button class="btn btn-primary btn-full">Verify</button>
      </form>
    </div>
    """)
    return page(content)


@app.route('/logout')
def logout():
    session.pop('member_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# ═══════════════════════════════════════════════════════════
# FORGOT / RESET PASSWORD
# ═══════════════════════════════════════════════════════════
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    ip = _client_ip()
    if request.method == 'POST':
        locked, attempts, key = _rate_check('reset', ip, _RESET_WINDOW, _RESET_MAX)
        if locked:
            flash('Too many reset requests. Try again later.', 'danger')
            return redirect(url_for('forgot_password'))

        email = sanitize(request.form.get('email', ''), 120).lower()
        success_msg = 'If that email is registered, a reset link has been sent.'

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
            display_name = (member.get('first_name') or member.get('full_name') or 'Odadeɛ')
            ok, err = mailer.send_password_reset(email, display_name, reset_url)
            if not ok:
                print(f'[forgot-password] Email failed: {err}')
                print(f'[forgot-password] Manual link: {reset_url}')

        _rate_record(key, attempts)
        flash(success_msg, 'info')
        return redirect(url_for('login'))

    content = render_template_string("""
    <div class="form-container">
      <h1>Forgot your password?</h1>
      <p class="form-subtitle">Enter your email and we'll send a reset link</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group"><label>Email</label>
          <input type="email" name="email" required autofocus></div>
        <button class="btn btn-primary btn-full">Send reset link</button>
      </form>
    </div>
    """)
    return page(content)


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token', '') or request.form.get('token', '')
    row = pr.verify_token(token)
    if not row:
        return page(render_template_string("""
        <div class="form-container" style="text-align:center;">
          <h1>Invalid or expired link</h1>
          <a href="{{ url_for('forgot_password') }}" class="btn btn-primary">Request a new link</a>
        </div>
        """))
    if request.method == 'POST':
        pwd = request.form.get('password', '')
        cnf = request.form.get('confirm', '')
        if len(pwd) < 8 or pwd != cnf:
            flash('Passwords must match and be at least 8 characters.', 'danger')
            return redirect(url_for('reset_password', token=token))
        ok, msg = pr.consume_token(token, pwd)
        flash(msg, 'success' if ok else 'danger')
        return redirect(url_for('login'))
    return page(render_template_string("""
    <div class="form-container">
      <h1>Choose a new password</h1>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="token" value="{{ token }}">
        <div class="form-group"><label>New password</label>
          <input type="password" name="password" required minlength="8" autofocus></div>
        <div class="form-group"><label>Confirm password</label>
          <input type="password" name="confirm" required minlength="8"></div>
        <button class="btn btn-primary btn-full">Update password</button>
      </form>
    </div>
    """, token=token))


# ═══════════════════════════════════════════════════════════
# MEMBER PROFILE EDIT + PASSWORD CHANGE + 2FA + LOGIN HISTORY
# ═══════════════════════════════════════════════════════════
@app.route('/profile', methods=['GET', 'POST'])
@member_required
def profile_page():
    m = current_member()
    if not m:
        return redirect(url_for('login'))

    if request.method == 'POST':
        updates = {
            'title':             sanitize(request.form.get('title', ''), 20),
            'first_name':        sanitize(request.form.get('first_name', ''), 120),
            'middle_name':       sanitize(request.form.get('middle_name', ''), 120),
            'last_name':         sanitize(request.form.get('last_name', ''), 120),
            'phone':             sanitize(request.form.get('phone', ''), 40),
            'house':             sanitize(request.form.get('house', ''), 60),
            'emergency_contact': sanitize(request.form.get('emergency_contact', ''), 200),
            'job_title':         sanitize(request.form.get('job_title', ''), 120),
            'industry':          sanitize(request.form.get('industry', ''), 120),
            'dob_day':           sanitize(request.form.get('dob_day', ''), 2),
            'dob_month':         sanitize(request.form.get('dob_month', ''), 20),
            'dob_year':          sanitize(request.form.get('dob_year', ''), 4),
        }
        updates['full_name'] = build_full_name(
            updates['first_name'], updates['middle_name'], updates['last_name'])

        if sb.SUPABASE_ENABLED:
            sb.update_where(T_MEMBERS, 'member_id', m['member_id'], updates)
        else:
            # CSV fallback
            df = load_csv(MEMBERS_FILE)
            if not df.empty:
                mask = df['member_id'] == m['member_id']
                for k, v in updates.items():
                    df.loc[mask, k] = v
                df.to_csv(MEMBERS_FILE, index=False)
        flash('Profile updated.', 'success')
        return redirect(url_for('profile_page'))

    content = render_template_string("""
    <div class="reports-header">
      <div><h1>✏️ My Profile</h1><p class="subtitle">Update your details</p></div>
      <div class="report-actions">
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a>
      </div>
    </div>

    <div class="form-container">
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-row">
          <div class="form-group"><label>Title</label>
            <select name="title">
              <option value="">—</option>
              {% for t in ['Mr','Mrs','Miss','Dr','Rev','Prof','Hon','Nana','Nii'] %}
              <option {% if m.get('title') == t %}selected{% endif %}>{{ t }}</option>
              {% endfor %}
            </select></div>
          <div class="form-group"><label>House</label>
            <input name="house" value="{{ m.get('house','') }}"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>First Name</label>
            <input name="first_name" value="{{ m.get('first_name','') }}"></div>
          <div class="form-group"><label>Middle Name</label>
            <input name="middle_name" value="{{ m.get('middle_name','') }}"></div>
        </div>
        <div class="form-group"><label>Last Name</label>
          <input name="last_name" value="{{ m.get('last_name','') }}"></div>
        <div class="form-row" style="grid-template-columns: 1fr 2fr 1fr;">
          <div class="form-group"><label>DOB Day</label>
            <input type="number" name="dob_day" min="1" max="31" value="{{ m.get('dob_day','') }}"></div>
          <div class="form-group"><label>DOB Month</label>
            <select name="dob_month">
              <option value="">—</option>
              {% for mo in months %}
              <option {% if m.get('dob_month') == mo %}selected{% endif %}>{{ mo }}</option>
              {% endfor %}
            </select></div>
          <div class="form-group"><label>DOB Year</label>
            <input type="number" name="dob_year" min="1900" max="2026" value="{{ m.get('dob_year','') }}"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Phone</label>
            <input name="phone" value="{{ m.get('phone','') }}"></div>
          <div class="form-group"><label>Emergency Contact</label>
            <input name="emergency_contact" value="{{ m.get('emergency_contact','') }}"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Job Title</label>
            <input name="job_title" value="{{ m.get('job_title','') }}"></div>
          <div class="form-group"><label>Industry</label>
            <input name="industry" value="{{ m.get('industry','') }}"></div>
        </div>
        <button class="btn btn-primary btn-full">Save Changes</button>
      </form>
      <p class="form-footer" style="margin-top:1rem;">
        <a href="{{ url_for('change_password_page') }}">Change password</a> •
        <a href="{{ url_for('two_factor_setup') }}">Two-factor authentication</a> •
        <a href="{{ url_for('login_history_page') }}">Login history</a>
      </p>
    </div>
    """, m=m, months=MONTHS)
    return page(content)


@app.route('/change-password', methods=['GET', 'POST'])
@member_required
def change_password_page():
    m = current_member()
    if request.method == 'POST':
        old = request.form.get('old_password', '')
        new = request.form.get('new_password', '')
        cnf = request.form.get('confirm', '')
        if not check_password_hash(m.get('password_hash', ''), old):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password_page'))
        if len(new) < 8:
            flash('New password must be at least 8 characters.', 'danger')
            return redirect(url_for('change_password_page'))
        if new != cnf:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('change_password_page'))
        sb.update_where(T_MEMBERS, 'member_id', m['member_id'],
                        {'password_hash': generate_password_hash(new)})
        flash('Password changed.', 'success')
        return redirect(url_for('profile_page'))
    return page(render_template_string("""
    <div class="form-container">
      <h1>Change password</h1>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="form-group"><label>Current password</label>
          <input type="password" name="old_password" required></div>
        <div class="form-group"><label>New password</label>
          <input type="password" name="new_password" required minlength="8"></div>
        <div class="form-group"><label>Confirm new password</label>
          <input type="password" name="confirm" required minlength="8"></div>
        <button class="btn btn-primary btn-full">Update password</button>
      </form>
    </div>
    """))


@app.route('/2fa-setup', methods=['GET', 'POST'])
@member_required
def two_factor_setup():
    m = current_member()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'enable':
            secret = request.form.get('secret', '')
            code = request.form.get('code', '')
            if tf.verify(secret, code):
                sb.update_where(T_MEMBERS, 'member_id', m['member_id'],
                                {'totp_secret': secret, 'totp_enabled': 'True'})
                flash('2FA enabled.', 'success')
                return redirect(url_for('profile_page'))
            flash('Invalid code.', 'danger')
            return redirect(url_for('two_factor_setup'))
        if action == 'disable':
            sb.update_where(T_MEMBERS, 'member_id', m['member_id'],
                            {'totp_secret': '', 'totp_enabled': 'False'})
            flash('2FA disabled.', 'info')
            return redirect(url_for('profile_page'))

    enabled = str(m.get('totp_enabled', 'False')).lower() == 'true'
    if enabled:
        return page(render_template_string("""
        <div class="form-container">
          <h1>Two-factor authentication</h1>
          <p class="form-subtitle">2FA is currently ENABLED on your account</p>
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="action" value="disable">
            <button class="btn btn-primary btn-full">Disable 2FA</button>
          </form>
        </div>
        """))

    secret = tf.new_secret()
    url = tf.provisioning_url(secret, m.get('email', 'member'))
    content = render_template_string("""
    <div class="form-container">
      <h1>Set up 2FA</h1>
      <p class="form-subtitle">Scan this URL in Google Authenticator or Authy</p>
      <div class="form-group">
        <label>Secret (add manually if you can't scan)</label>
        <input value="{{ secret }}" readonly>
      </div>
      <p style="color:#6c757d;font-size:0.85rem;word-break:break-all;">{{ otpauth }}</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="enable">
        <input type="hidden" name="secret" value="{{ secret }}">
        <div class="form-group"><label>Enter code from your app</label>
          <input name="code" required maxlength="6" inputmode="numeric"></div>
        <button class="btn btn-primary btn-full">Enable 2FA</button>
      </form>
    </div>
    """, secret=secret, otpauth=url)
    return page(content)


@app.route('/login-history')
@member_required
def login_history_page():
    m = current_member()
    rows = [r for r in sb.fetch_all('login_history')
            if r.get('subject_id') == m['member_id']
            or r.get('ip_address') == _client_ip()][:50]
    content = render_template_string("""
    <div class="reports-header">
      <div><h1>🔐 Login history</h1><p class="subtitle">Last 50 events</p></div>
      <div class="report-actions">
        <a href="{{ url_for('profile_page') }}" class="btn btn-secondary">← Profile</a>
      </div>
    </div>
    <div class="table-wrapper">
      <table class="report-table full-width">
        <thead><tr><th>When</th><th>IP</th><th>Result</th><th>Device</th></tr></thead>
        <tbody>
        {% for r in rows %}
        <tr>
          <td>{{ r.happened_at[:19] }}</td>
          <td>{{ r.ip_address }}</td>
          <td>{{ '✅ Success' if r.success == 'True' else '❌ Failed' }}</td>
          <td style="font-size:0.8rem;color:#666;">{{ r.user_agent[:60] }}</td>
        </tr>
        {% else %}
        <tr><td colspan="4" class="empty-state">No login history yet.</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    """, rows=rows)
    return page(content)


# ═══════════════════════════════════════════════════════════
# DASHBOARD (with charts)
# ═══════════════════════════════════════════════════════════
@app.route('/dashboard')
@member_required
def dashboard():
    m = current_member()
    if not m:
        session.pop('member_id', None)
        return redirect(url_for('login'))

    votes    = load_table(T_VOTES, VOTES_FILE)
    dues     = load_table(T_DUES, DUES_FILE)
    contribs = load_table(T_CONTRIBUTIONS, CONTRIBUTIONS_FILE)
    members  = load_table(T_MEMBERS, MEMBERS_FILE)

    my_votes   = len(votes[votes['member_id'] == m['member_id']]) if not votes.empty else 0
    my_dues    = safe_amount(pd.to_numeric(dues[dues['member_id'] == m['member_id']]['amount'], errors='coerce').fillna(0).sum()) if not dues.empty else 0
    my_contrib = safe_amount(pd.to_numeric(contribs[contribs['member_id'] == m['member_id']]['amount'], errors='coerce').fillna(0).sum()) if not contribs.empty else 0

    # Monthly dues chart
    labels, values = [], []
    if not dues.empty:
        df = dues.copy()
        df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0)
        df['month'] = df['created_at'].str[:7]
        g = df.groupby('month')['amount'].sum().sort_index()
        labels = list(g.index)
        values = [float(v) for v in g.values]

    dues_chart = line_chart('dues-chart', labels, values) if labels else ''

    full_display = ' '.join(filter(None, [
        m.get('title',''), m.get('first_name',''),
        m.get('middle_name',''), m.get('last_name','')
    ])) or m.get('full_name','')

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

    {% if dues_chart %}
    <div class="report-section">
      <h2>📈 Dues collected over time</h2>
      {{ dues_chart|safe }}
    </div>
    {% endif %}

    <div class="admin-actions">
      <a href="{{ url_for('polls_page') }}"          class="btn btn-primary">🗳️ Vote in Polls</a>
      <a href="{{ url_for('dues_page') }}"           class="btn btn-primary">📅 Pay Dues</a>
      <a href="{{ url_for('contributions_page') }}"  class="btn btn-primary">🎯 Contribute</a>
      <a href="{{ url_for('profile_page') }}"        class="btn btn-secondary">✏️ Edit Profile</a>
    </div>
    """, m=m, display_name=full_display,
         my_votes=my_votes, my_dues=my_dues, my_contrib=my_contrib,
         member_count=len(members), dues_chart=dues_chart)
    return page(content)


# ═══════════════════════════════════════════════════════════
# MEMBERS DIRECTORY (with search)
# ═══════════════════════════════════════════════════════════
@app.route('/members')
@member_required
def members_directory():
    q = sanitize(request.args.get('q', ''), 100).lower()
    df = load_table(T_MEMBERS, MEMBERS_FILE)
    if not df.empty and 'password_hash' in df.columns:
        df = df.drop(columns=['password_hash'])
    members = df.to_dict('records') if not df.empty else []
    if q:
        members = [m for m in members if q in (
            (m.get('full_name','') + ' ' +
             m.get('first_name','') + ' ' +
             m.get('middle_name','') + ' ' +
             m.get('last_name','') + ' ' +
             m.get('email','') + ' ' +
             m.get('house','') + ' ' +
             m.get('job_title','')).lower()
        )]

    content = render_template_string("""
    <div class="reports-header">
      <div><h1>👥 Directory</h1><p class="subtitle">{{ members|length }} match(es)</p></div>
    </div>
    <div class="form-container" style="max-width:640px;margin-bottom:1rem;">
      <form method="GET">
        <div class="form-group" style="display:flex;gap:0.5rem;align-items:end;">
          <div style="flex:1;">
            <label>Search by name, email, house, job</label>
            <input name="q" value="{{ q }}" placeholder="Type to search...">
          </div>
          <button class="btn btn-primary">Search</button>
        </div>
      </form>
    </div>
    <div class="table-wrapper">
      <table class="report-table full-width">
        <thead><tr>
          <th>Name</th><th>Email</th><th>Phone</th><th>House</th><th>Job</th>
        </tr></thead>
        <tbody>
        {% for m in members %}
          <tr>
            <td><strong>{{ m.get('title','') }} {{ m.get('first_name') or m.get('full_name','') }} {{ m.get('last_name','') }}</strong></td>
            <td>{{ m.email }}</td>
            <td>{{ m.phone or '—' }}</td>
            <td>{{ m.house or '—' }}</td>
            <td>{{ m.get('job_title','') or '—' }}</td>
          </tr>
        {% else %}
          <tr><td colspan="5" class="empty-state">No members matched.</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    """, members=members, q=q)
    return page(content)


# ═══════════════════════════════════════════════════════════
# POLLS (respecting schedule + anonymity)
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

        polls = load_table(T_POLLS, POLLS_FILE)
        p = polls[polls['poll_id'] == poll_id] if not polls.empty else pd.DataFrame()
        if p.empty or not poll_is_open(p.iloc[0].to_dict()):
            flash('This poll is not currently open.', 'danger')
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
        flash('✅ Vote recorded.', 'success')
        return redirect(url_for('polls_page'))

    polls = load_table(T_POLLS, POLLS_FILE)
    votes = load_table(T_VOTES, VOTES_FILE)
    my_votes = set(votes[votes['member_id'] == session['member_id']]['poll_id'].tolist()) if not votes.empty else set()

    poll_list = []
    if not polls.empty:
        for _, p in polls.iterrows():
            if not poll_is_open(p.to_dict()):
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
      <div><h1>🗳️ Active Polls</h1><p class="subtitle">{{ polls|length }} open</p></div>
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
    <p class="empty-state">No open polls right now.</p>
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
            flash(f'✅ Payment of GH₵{amount:.2f} recorded.', 'success')
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
      <div><h1>📅 Dues</h1><p class="subtitle">Pay for open periods</p></div>
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
            <div class="form-group"><label>Amount</label>
              <input type="number" step="0.01" name="amount"
                     value="{{ "%.2f"|format(d.amount) }}" required></div>
            <div class="form-group"><label>Method</label>
              <select name="method"><option>Mobile Money</option>
              <option>Bank Transfer</option><option>Cash</option></select></div>
          </div>
          <button class="btn btn-primary">Pay Dues</button>
        </form>
      {% endif %}
    </div>
    {% else %}<p class="empty-state">No open dues periods.</p>{% endfor %}
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
            flash(f'✅ Contribution of GH₵{amount:.2f} recorded.', 'success')
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
      <div><h1>🎯 Contributions</h1></div>
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
        <strong>GH₵{{ "%.2f"|format(c.raised) }}</strong> of GH₵{{ "%.2f"|format(c.target) }}
      </p>
      <form method="POST" style="margin-top:1rem;">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="campaign_id" value="{{ c.id }}">
        <div class="form-row">
          <div class="form-group"><label>Amount</label>
            <input type="number" step="0.01" name="amount" required></div>
          <div class="form-group"><label>Method</label>
            <select name="method"><option>Mobile Money</option>
            <option>Bank Transfer</option><option>Cash</option></select></div>
        </div>
        <button class="btn btn-primary">Contribute</button>
      </form>
    </div>
    {% else %}<p class="empty-state">No campaigns.</p>{% endfor %}
    """, camps=rows)
    return page(content)


# ═══════════════════════════════════════════════════════════
# HEALTH + DEBUG
# ═══════════════════════════════════════════════════════════
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'supabase_enabled': sb.SUPABASE_ENABLED,
        'email_enabled': mailer.EMAIL_ENABLED,
        'two_factor_available': True,
        'time': datetime.now().isoformat()
    })


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)