"""
app.py - Odadeɛ07 Year Group PII Collection, Contribution, Voting, Dues & Gallery System
Presbyterian Boys' Secondary School, 2007 Year Group

Deployment modes:
  - LOCAL (default): CSV files in data/ + optional HTTPS with mkcert certs
  - CLOUD (Render/Railway): Supabase (Postgres) for persistent data + HTTPS at edge

Environment variables (cloud):
  SUPABASE_URL         - e.g. https://xxx.supabase.co
  SUPABASE_KEY         - Supabase anon key
  SECRET_KEY           - random 64-char string
  ADMIN_PASSWORD       - strong admin password
  IMGBB_API_KEY        - free API key from https://api.imgbb.com
  RENDER               - set automatically by Render (or "true" manually)
  HTTPS_ENABLED        - "true" to force HTTPS redirect + secure cookies
"""

import os
import sys
import random
import time
import io
import json
import csv
import re
import zipfile
import ssl
import requests
from datetime import datetime
from functools import wraps
from io import BytesIO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Optional dotenv for local dev
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, '.env'))
except ImportError:
    pass

from flask import (Flask, render_template_string, request, session, redirect,
                   url_for, send_file, jsonify, flash, make_response, abort)
import pandas as pd
import numpy as np
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Optional Supabase
try:
    from supabase import create_client, Client
except ImportError:
    create_client = None
    Client = None

# =============================================================
# CONFIGURATION
# =============================================================
app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'odadea07_dev_only_change_me_2024')

app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['GALLERY_FOLDER'] = os.path.join(BASE_DIR, 'static', 'gallery')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# ---- Environment detection ----
BEHIND_PROXY = bool(os.environ.get('RENDER') or os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('FLY_APP_NAME'))

# ---- HTTPS detection ----
CERT_FILE = os.path.join(BASE_DIR, 'certs', 'localhost+2.pem')
KEY_FILE = os.path.join(BASE_DIR, 'certs', 'localhost+2-key.pem')
CERTS_PRESENT = os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)

HTTPS_ENABLED = BEHIND_PROXY or CERTS_PRESENT or (os.environ.get('HTTPS_ENABLED', 'false').lower() == 'true')

# ---- Supabase detection ----
SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY and create_client)

supabase = None
if USE_SUPABASE:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("✅ Supabase connected")
    except Exception as e:
        print(f"⚠️ Supabase connection failed: {e}")
        USE_SUPABASE = False
        supabase = None

# ---- ImgBB detection ----
IMGBB_API_KEY = os.environ.get('IMGBB_API_KEY', '')
USE_IMGBB = bool(IMGBB_API_KEY)

# Session hardening — Secure cookies only when running HTTPS
app.config['SESSION_COOKIE_SECURE'] = HTTPS_ENABLED
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 7
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Ensure directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['GALLERY_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'static', 'css'), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'static', 'images'), exist_ok=True)

DATA_DIR = os.path.join(BASE_DIR, 'data')
MEMBERS_FILE = os.path.join(DATA_DIR, 'members.csv')
CONTRIBUTIONS_FILE = os.path.join(DATA_DIR, 'contributions.csv')
VOTES_FILE = os.path.join(DATA_DIR, 'votes.csv')
POLLS_FILE = os.path.join(DATA_DIR, 'polls.csv')
GALLERY_FILE = os.path.join(DATA_DIR, 'gallery.csv')
CAMPAIGNS_FILE = os.path.join(DATA_DIR, 'contributions_campaigns.csv')
DUES_CAMPAIGNS_FILE = os.path.join(DATA_DIR, 'dues_campaigns.csv')
DUES_FILE = os.path.join(DATA_DIR, 'dues.csv')

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'odadea07admin')

# =============================================================
# SECURITY MIDDLEWARE
# =============================================================
limiter = Limiter(key_func=get_remote_address, app=app,
                  default_limits=["300 per day", "100 per hour"], storage_uri="memory://")
csrf = CSRFProtect(app)


@app.before_request
def enforce_https():
    if HTTPS_ENABLED:
        if BEHIND_PROXY:
            if request.headers.get('X-Forwarded-Proto', 'http') != 'https':
                return redirect(request.url.replace('http://', 'https://', 1), code=301)
        else:
            host = request.host
            if 'localhost' not in host and '127.0.0.1' not in host:
                if request.headers.get('X-Forwarded-Proto', 'http') != 'https':
                    return redirect(request.url.replace('http://', 'https://', 1), code=301)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    if HTTPS_ENABLED:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


app.jinja_env.globals['csrf_token'] = generate_csrf


# =============================================================
# IMAGE HOSTING (ImgBB) — persists across restarts on free hosts
# =============================================================
def upload_to_imgbb(file_storage):
    """Upload a file to ImgBB and return the direct URL, or None on failure."""
    if not USE_IMGBB:
        return None
    try:
        image_bytes = file_storage.read()
        resp = requests.post(
            'https://api.imgbb.com/1/upload',
            params={'key': IMGBB_API_KEY},
            files={'image': image_bytes},
            timeout=30
        )
        result = resp.json()
        if result.get('success'):
            return result['data']['url']
        print(f"ImgBB error: {result}")
    except Exception as e:
        print(f"ImgBB upload failed: {e}")
    return None


def save_upload(file_storage, folder, prefix):
    """
    Save an uploaded file. Prefers ImgBB (returns full URL).
    Falls back to local filesystem (returns just the filename).
    """
    if not file_storage or not file_storage.filename:
        return ''
    # Try ImgBB first (cloud persistence)
    if USE_IMGBB:
        url = upload_to_imgbb(file_storage)
        if url:
            return url
    # Local fallback (works only on non-ephemeral filesystems)
    fn = secure_filename(f"{prefix}_{file_storage.filename}")
    file_storage.seek(0)
    file_storage.save(os.path.join(folder, fn))
    return fn


# =============================================================
# DATA HELPERS — dual mode (Supabase or CSV)
# =============================================================

def _df_from_response(response):
    """Convert Supabase response to DataFrame"""
    if response and hasattr(response, 'data') and response.data:
        return pd.DataFrame(response.data).fillna('')
    return pd.DataFrame()


def _sb_select(table):
    """Select all rows from a Supabase table"""
    try:
        resp = supabase.table(table).select('*').execute()
        return _df_from_response(resp)
    except Exception as e:
        print(f"Supabase select error [{table}]: {e}")
        return pd.DataFrame()


def _sb_insert(table, data):
    """Insert a row into a Supabase table"""
    try:
        supabase.table(table).insert(data).execute()
        return True
    except Exception as e:
        print(f"Supabase insert error [{table}]: {e}")
        return False


def _sb_update(table, id_col, id_val, updates):
    """Update a row in Supabase"""
    try:
        supabase.table(table).update(updates).eq(id_col, id_val).execute()
        return True
    except Exception as e:
        print(f"Supabase update error [{table}]: {e}")
        return False


def _sb_delete(table, id_col, id_val):
    """Delete a row from Supabase"""
    try:
        supabase.table(table).delete().eq(id_col, id_val).execute()
        return True
    except Exception as e:
        print(f"Supabase delete error [{table}]: {e}")
        return False


def load_csv(path):
    """Local CSV loader"""
    if os.path.exists(path):
        return pd.read_csv(path).fillna('')
    return pd.DataFrame()


def append_row(path, data, sb_table=None):
    """Append row to CSV (local) OR Supabase (cloud)"""
    if USE_SUPABASE and sb_table:
        # Normalize values for Supabase
        clean = {}
        for k, v in data.items():
            if isinstance(v, (pd.Timestamp, datetime)):
                clean[k] = v.isoformat()
            elif isinstance(v, (np.integer,)):
                clean[k] = int(v)
            elif isinstance(v, (np.floating,)):
                clean[k] = float(v)
            else:
                clean[k] = v
        _sb_insert(sb_table, clean)
        return

    # CSV fallback
    df = load_csv(path)
    new = pd.DataFrame([data])
    updated = pd.concat([df, new], ignore_index=True) if not df.empty else new
    updated.to_csv(path, index=False)


# ---- Data loaders ----

def load_members():
    if USE_SUPABASE: return _sb_select('members')
    return load_csv(MEMBERS_FILE)

def load_contributions():
    if USE_SUPABASE: return _sb_select('contributions')
    return load_csv(CONTRIBUTIONS_FILE)

def load_polls():
    if USE_SUPABASE: return _sb_select('polls')
    return load_csv(POLLS_FILE)

def load_votes():
    if USE_SUPABASE: return _sb_select('votes')
    return load_csv(VOTES_FILE)

def load_gallery():
    if USE_SUPABASE: return _sb_select('gallery')
    return load_csv(GALLERY_FILE)

def load_campaigns():
    if USE_SUPABASE: return _sb_select('campaigns')
    return load_csv(CAMPAIGNS_FILE)

def load_dues_campaigns():
    if USE_SUPABASE: return _sb_select('dues_campaigns')
    return load_csv(DUES_CAMPAIGNS_FILE)

def load_dues():
    if USE_SUPABASE: return _sb_select('dues')
    return load_csv(DUES_FILE)


# ---- Auth helpers ----

def verify_member(email, password):
    df = load_members()
    if df.empty: return None
    m = df[df['email'].astype(str).str.lower() == email.lower()]
    if m.empty: return None
    if check_password_hash(str(m.iloc[0]['password_hash']), password):
        return m.iloc[0].to_dict()
    return None


def get_member_by_id(member_id):
    df = load_members()
    if df.empty: return None
    m = df[df['member_id'] == member_id]
    return m.iloc[0].to_dict() if not m.empty else None


def has_voted(member_id, poll_id):
    df = load_votes()
    if df.empty: return False
    return not df[(df['member_id'] == member_id) & (df['poll_id'] == poll_id)].empty


def strong_password(pw):
    if len(pw) < 8: return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', pw): return False, "Needs an uppercase letter"
    if not re.search(r'[a-z]', pw): return False, "Needs a lowercase letter"
    if not re.search(r'\d', pw):    return False, "Needs a number"
    return True, "OK"


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'member_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get('is_admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*a, **kw)
    return wrapper


# =============================================================
# BASE LAYOUT
# =============================================================
BASE_LAYOUT = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>Odadeɛ07 — PRESEC 2007 Year Group</title>
<meta name="theme-color" content="#1a3fbf">
<link rel="icon" type="image/png" href="{{ url_for('static', filename='images/presec-badge.png') }}">
<link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
<header class="main-header">
    <div class="header-content">
        <a href="{{ url_for('index') }}" class="logo-section">
            <img src="{{ url_for('static', filename='images/presec-badge.png') }}" class="school-badge" onerror="this.style.display='none'">
            <div class="logo-text">
                <h1>Odadeɛ07</h1>
                <p>Presbyterian Boys' Secondary School • 2007 Year Group</p>
            </div>
        </a>
        <nav class="main-nav">
            <a href="{{ url_for('index') }}">🏠 Home</a>
            {% if session.member_id %}
                <a href="{{ url_for('members') }}">👥 Members</a>
                <a href="{{ url_for('gallery') }}">🖼️ Gallery</a>
                <a href="{{ url_for('vote_index') }}">🗳️ Vote</a>
                <a href="{{ url_for('campaigns_index') }}">🎯 Campaigns</a>
                <a href="{{ url_for('dues_index') }}">📅 Dues</a>
                <a href="{{ url_for('dashboard') }}">📊 Dashboard</a>
                <a href="{{ url_for('logout') }}" class="btn-logout">Logout ({{ session.member_name.split()[0] }})</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}" class="btn-register">Register</a>
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
<main class="main-content">{{ page_content|safe }}</main>
<footer class="main-footer">
    <div class="footer-content">
        <p><strong>Odadeɛ07</strong> — Presbyterian Boys' Secondary School, 2007 Year Group</p>
        <p class="motto">"In Lumine Tuo Videbimus Lumen"</p>
        <p>© {{ year }} Odadeɛ07. All rights reserved.</p>
    </div>
</footer>
</body>
</html>
"""


def render_page(content, **ctx):
    ctx.setdefault('year', datetime.now().year)
    ctx['page_content'] = content
    return render_template_string(BASE_LAYOUT, **ctx)


CSRF_INPUT = '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">'


# =============================================================
# PUBLIC ROUTES
# =============================================================
@app.route('/')
def index():
    polls = load_polls()
    campaigns = load_campaigns()
    active_campaigns = campaigns[campaigns['active'].astype(str).str.lower().isin(['true','1','yes'])] if not campaigns.empty else pd.DataFrame()

    content = render_template_string(r"""
<div class="hero-section">
    <div class="hero-content">
        <img src="{{ url_for('static', filename='images/presec-badge.png') }}" class="school-badge">
        <h1>Welcome to Odadeɛ07</h1>
        <p class="hero-subtitle">Presbyterian Boys' Secondary School • 2007 Year Group</p>
        <p class="hero-motto">"In Lumine Tuo Videbimus Lumen"</p>
        {% if session.member_id %}
        <div class="hero-actions">
            <a href="{{ url_for('campaigns_index') }}" class="btn btn-primary">🎯 Campaigns</a>
            <a href="{{ url_for('dues_index') }}" class="btn btn-secondary">📅 Dues</a>
            <a href="{{ url_for('vote_index') }}" class="btn btn-secondary">🗳️ Vote</a>
        </div>
        {% endif %}
    </div>
</div>

{% if session.member_id and active_campaigns %}
<section class="polls-section">
    <h2>🎯 Active Campaigns</h2>
    <div class="polls-grid">
        {% for c in active_campaigns %}
        <div class="poll-card">
            <h3>{{ c.title }}</h3>
            <p>{{ c.description }}</p>
            <a href="{{ url_for('campaign_detail', campaign_id=c.campaign_id) }}" class="btn btn-primary">View & Pay</a>
        </div>
        {% endfor %}
    </div>
</section>
{% endif %}
""", active_campaigns=active_campaigns.to_dict('records') if not active_campaigns.empty else [])
    return render_page(content)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    if request.method == 'POST':
        data = {
            'member_id': f"ODA{int(time.time())}_{random.randint(100, 999)}",
            'full_name': request.form.get('full_name', '').strip(),
            'email': request.form.get('email', '').strip().lower(),
            'phone': request.form.get('phone', '').strip(),
            'house': request.form.get('house', '').strip(),
            'occupation': request.form.get('occupation', '').strip(),
            'location': request.form.get('location', '').strip(),
            'bio': request.form.get('bio', '').strip(),
            'password_hash': generate_password_hash(request.form.get('password', '')),
            'photo_filename': '',
            'registered_at': datetime.now().isoformat()
        }
        if not data['full_name'] or not data['email'] or not data['phone']:
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('register'))
        ok, msg = strong_password(request.form.get('password', ''))
        if not ok:
            flash(msg, 'danger'); return redirect(url_for('register'))
        # Upload profile photo (ImgBB preferred)
        if 'photo' in request.files:
            photo = request.files['photo']
            if photo and photo.filename:
                data['photo_filename'] = save_upload(
                    photo, app.config['UPLOAD_FOLDER'], data['member_id']
                )
        df = load_members()
        if not df.empty and data['email'] in df['email'].astype(str).str.lower().values:
            flash('Email already registered.', 'danger'); return redirect(url_for('register'))
        append_row(MEMBERS_FILE, data, sb_table='members')
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    content = render_template_string(r"""
<div class="form-container">
    <h1>Join Odadeɛ07</h1>
    <p class="form-subtitle">Register with your details and upload a photo</p>
    <form method="POST" enctype="multipart/form-data">
        """ + CSRF_INPUT + r"""
        <div class="form-group"><label>Full Name *</label><input type="text" name="full_name" required></div>
        <div class="form-group"><label>Email Address *</label><input type="email" name="email" required></div>
        <div class="form-group"><label>Phone Number *</label><input type="tel" name="phone" required></div>
        <div class="form-row">
            <div class="form-group"><label>House</label>
                <select name="house">
                    <option value="">Select House</option>
                    <option>Kwansa</option><option>Clerk</option><option>Engmann</option>
                    <option>Akro</option><option>Riis</option><option>Labone</option>
                    <option>Ako-Adjei</option><option>Owusu-Parry</option>
                    <option>House 9</option><option>PTA</option>
                </select>
            </div>
            <div class="form-group"><label>Occupation</label><input type="text" name="occupation"></div>
        </div>
        <div class="form-group"><label>Location</label><input type="text" name="location"></div>
        <div class="form-group"><label>Short Bio</label><textarea name="bio" rows="3"></textarea></div>
        <div class="form-group"><label>Profile Photo</label>
            <input type="file" name="photo" accept="image/*" class="file-input">
        </div>
        <div class="form-group"><label>Password *</label>
            <input type="password" name="password" minlength="8" required>
            <small>Min 8 chars, 1 uppercase, 1 lowercase, 1 number</small>
        </div>
        <button type="submit" class="btn btn-primary btn-full">🎓 Register</button>
    </form>
    <p class="form-footer">Already registered? <a href="{{ url_for('login') }}">Log in</a></p>
</div>
""")
    return render_page(content)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        pw = request.form.get('password', '')
        m = verify_member(email, pw)
        if m:
            session['member_id'] = m['member_id']
            session['member_name'] = m['full_name']
            session.permanent = True
            flash(f'Welcome back, {m["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')

    content = render_template_string(r"""
<div class="form-container">
    <h1>Member Login</h1>
    <p class="form-subtitle">Welcome back, Odadeɛ</p>
    <form method="POST">
        """ + CSRF_INPUT + r"""
        <div class="form-group"><label>Email</label><input type="email" name="email" required autofocus></div>
        <div class="form-group"><label>Password</label><input type="password" name="password" required></div>
        <button type="submit" class="btn btn-primary btn-full">🔐 Log In</button>
    </form>
    <p class="form-footer">Not registered? <a href="{{ url_for('register') }}">Join</a></p>
</div>
""")
    return render_page(content)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# =============================================================
# DASHBOARD
# =============================================================
@app.route('/dashboard')
@login_required
def dashboard():
    member = get_member_by_id(session['member_id'])
    contributions = load_contributions()
    dues = load_dues()
    gallery_df = load_gallery()
    campaigns = load_campaigns()
    dues_campaigns = load_dues_campaigns()

    my_c = contributions[contributions['member_id'] == session['member_id']].to_dict('records') if not contributions.empty and 'member_id' in contributions.columns else []
    my_d = dues[dues['member_id'] == session['member_id']].to_dict('records') if not dues.empty and 'member_id' in dues.columns else []
    my_total = sum(float(c['amount']) for c in my_c) if my_c else 0
    my_dues_total = sum(float(c['amount']) for c in my_d) if my_d else 0

    my_gallery = len(gallery_df[gallery_df['member_id'] == session['member_id']]) if not gallery_df.empty else 0
    total_gallery = len(gallery_df) if not gallery_df.empty else 0

    active_campaigns = campaigns[campaigns['active'].astype(str).str.lower().isin(['true','1','yes'])] if not campaigns.empty else pd.DataFrame()
    open_dues = dues_campaigns[dues_campaigns['active'].astype(str).str.lower().isin(['true','1','yes'])] if not dues_campaigns.empty else pd.DataFrame()

    content = render_template_string(r"""
<div class="dash-page">
    <div class="dashboard-header">
        <div class="member-info">
            {% if member.photo_filename %}
                <img src="{{ member.photo_filename if member.photo_filename.startswith('http') else url_for('static', filename='uploads/' + member.photo_filename) }}" class="member-photo">
            {% else %}
                <div class="member-photo-placeholder">{{ member.full_name[0] }}</div>
            {% endif %}
            <div>
                <h1>Welcome back, {{ member.full_name }}</h1>
                <p>{{ member.house or 'Odadeɛ' }} House • {{ member.occupation or 'Odadeɛ' }} • {{ member.location or 'Ghana' }}</p>
            </div>
        </div>
    </div>

    <div class="dash-stats-bar">
        <div class="dash-stat"><div class="dash-stat-icon">💰</div>
            <div class="dash-stat-text">
                <span class="dash-stat-value">GH₵{{ "%.2f"|format(my_total) }}</span>
                <span class="dash-stat-label">My Contributions</span>
            </div>
        </div>
        <div class="dash-stat"><div class="dash-stat-icon">📅</div>
            <div class="dash-stat-text">
                <span class="dash-stat-value">GH₵{{ "%.2f"|format(my_dues_total) }}</span>
                <span class="dash-stat-label">My Dues Paid</span>
            </div>
        </div>
        <div class="dash-stat"><div class="dash-stat-icon">🖼️</div>
            <div class="dash-stat-text">
                <span class="dash-stat-value">{{ my_gallery }}</span>
                <span class="dash-stat-label">My Photos</span>
            </div>
        </div>
        <div class="dash-stat"><div class="dash-stat-icon">🎯</div>
            <div class="dash-stat-text">
                <span class="dash-stat-value">{{ active_campaigns|length }}</span>
                <span class="dash-stat-label">Active Campaigns</span>
            </div>
        </div>
    </div>

    <div class="dash-card-horizontal">
        <div class="dash-card-left">
            <div class="dash-card-icon-lg">🎯</div>
            <div class="dash-card-heading">
                <h2>Contribution Campaigns</h2>
                <p class="dash-card-sub">{{ active_campaigns|length }} active</p>
            </div>
        </div>
        <div class="dash-card-mid">
            <div class="dash-big-number">GH₵{{ "%.2f"|format(my_total) }}</div>
            <div class="dash-big-label">paid by you</div>
        </div>
        <div class="dash-card-right">
            <a href="{{ url_for('campaigns_index') }}" class="btn btn-primary">🎯 View Campaigns</a>
        </div>
    </div>

    <div class="dash-card-horizontal">
        <div class="dash-card-left">
            <div class="dash-card-icon-lg">📅</div>
            <div class="dash-card-heading">
                <h2>Monthly Dues</h2>
                <p class="dash-card-sub">{{ open_dues|length }} month{{ 's' if open_dues|length != 1 else '' }} open</p>
            </div>
        </div>
        <div class="dash-card-mid">
            <div class="dash-big-number">GH₵{{ "%.2f"|format(my_dues_total) }}</div>
            <div class="dash-big-label">dues paid</div>
        </div>
        <div class="dash-card-right">
            <a href="{{ url_for('dues_index') }}" class="btn btn-primary">📅 View Dues</a>
        </div>
    </div>

    <div class="dash-card-horizontal">
        <div class="dash-card-left">
            <div class="dash-card-icon-lg">🖼️</div>
            <div class="dash-card-heading">
                <h2>Gallery</h2>
                <p class="dash-card-sub">{{ total_gallery }} photo{{ 's' if total_gallery != 1 else '' }} shared</p>
            </div>
        </div>
        <div class="dash-card-mid">
            <div class="dash-big-number">{{ my_gallery }}</div>
            <div class="dash-big-label">uploaded</div>
        </div>
        <div class="dash-card-right">
            <a href="{{ url_for('gallery') }}" class="btn btn-primary">🖼️ Browse</a>
            <a href="{{ url_for('gallery_upload') }}" class="btn btn-secondary" style="margin-top:0.5rem;">⬆️ Upload</a>
        </div>
    </div>

    <div class="dash-card-horizontal">
        <div class="dash-card-left">
            <div class="dash-card-icon-lg">👥</div>
            <div class="dash-card-heading">
                <h2>Member Directory</h2>
                <p class="dash-card-sub">Connect with 2007 classmates</p>
            </div>
        </div>
        <div class="dash-card-mid">
            <div class="dash-big-number">👥</div>
            <div class="dash-big-label">PRESEC 2007</div>
        </div>
        <div class="dash-card-right">
            <a href="{{ url_for('members') }}" class="btn btn-primary">👥 View Members</a>
        </div>
    </div>
</div>
""", member=member, my_total=my_total, my_dues_total=my_dues_total,
     my_gallery=my_gallery, total_gallery=total_gallery,
     active_campaigns=active_campaigns, open_dues=open_dues)
    return render_page(content)


# =============================================================
# CONTRIBUTION CAMPAIGNS
# =============================================================
@app.route('/campaigns')
@login_required
def campaigns_index():
    campaigns = load_campaigns()
    contributions = load_contributions()

    items = []
    if not campaigns.empty:
        for _, c in campaigns.iterrows():
            if str(c.get('active', True)).lower() not in ['true','1','yes']:
                continue
            cid = c['campaign_id']
            target = float(c.get('target_amount', 0) or 0)
            contribs = contributions[contributions['campaign_id'] == cid] if not contributions.empty and 'campaign_id' in contributions.columns else pd.DataFrame()
            raised = float(pd.to_numeric(contribs['amount'], errors='coerce').fillna(0).sum()) if not contribs.empty else 0
            my_paid = contribs[contribs['member_id'] == session['member_id']] if not contribs.empty else pd.DataFrame()
            my_amount = float(pd.to_numeric(my_paid['amount'], errors='coerce').fillna(0).sum()) if not my_paid.empty else 0
            pct = min((raised / target * 100) if target else 0, 100)
            items.append({
                'campaign_id': cid, 'title': c['title'],
                'description': c.get('description', ''),
                'target_amount': target, 'raised': raised, 'pct': pct,
                'raw_pct': round((raised / target * 100) if target else 0, 1),
                'my_amount': my_amount
            })

    content = render_template_string(r"""
<div class="reports-header">
    <div>
        <h1>🎯 Contribution Campaigns</h1>
        <p class="subtitle">Help the year group reach its goals</p>
    </div>
    <div class="report-actions">
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a>
    </div>
</div>

{% if items %}
{% for c in items %}
<div class="poll-report-card">
    <div class="poll-report-header">
        <div>
            <h2>{{ c.title }}</h2>
            <p>{{ c.description }}</p>
        </div>
        <div class="poll-totals">
            <div class="poll-total-value">GH₵{{ "%.2f"|format(c.raised) }}</div>
            <div class="poll-total-label">of GH₵{{ "%.2f"|format(c.target_amount) }}</div>
            <div class="poll-turnout">{{ c.raw_pct }}% funded</div>
        </div>
    </div>
    <div class="progress-track">
        <div class="progress-fill {% if c.pct >= 100 %}full{% endif %}" style="width:{{ c.pct }}%"></div>
    </div>
    {% if c.my_amount > 0 %}
        <p style="margin-top:0.75rem;color:#16a34a;font-weight:700;">✓ You have contributed GH₵{{ "%.2f"|format(c.my_amount) }}</p>
    {% endif %}
    <div style="margin-top:1rem;">
        <a href="{{ url_for('campaign_detail', campaign_id=c.campaign_id) }}" class="btn btn-primary">💰 Contribute</a>
    </div>
</div>
{% endfor %}
{% else %}
<div class="recent-section">
    <h2>No active campaigns</h2>
    <p class="empty-state">Check back soon!</p>
</div>
{% endif %}
""", items=items)
    return render_page(content)


@app.route('/campaigns/<campaign_id>', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per hour")
def campaign_detail(campaign_id):
    campaigns = load_campaigns()
    if campaigns.empty:
        flash('Campaign not found.', 'danger'); return redirect(url_for('campaigns_index'))
    row = campaigns[campaigns['campaign_id'] == campaign_id]
    if row.empty:
        flash('Campaign not found.', 'danger'); return redirect(url_for('campaigns_index'))
    c = row.iloc[0].to_dict()
    target = float(c.get('target_amount', 0) or 0)

    if request.method == 'POST':
        try:
            amt = float(request.form.get('amount', '0') or 0)
        except ValueError:
            amt = 0
        if amt <= 0:
            flash('Please enter a valid amount.', 'danger'); return redirect(url_for('campaign_detail', campaign_id=campaign_id))
        append_row(CONTRIBUTIONS_FILE, {
            'contribution_id': f"CON{int(time.time())}_{random.randint(100, 999)}",
            'member_id': session['member_id'],
            'member_name': session['member_name'],
            'campaign_id': campaign_id,
            'campaign_title': c['title'],
            'amount': amt,
            'method': request.form.get('method', ''),
            'note': request.form.get('note', '').strip(),
            'status': 'completed',
            'created_at': datetime.now().isoformat()
        }, sb_table='contributions')
        flash(f'Thank you! GH₵{amt:.2f} contributed to "{c["title"]}".', 'success')
        return redirect(url_for('campaigns_index'))

    contribs = load_contributions()
    camp_contribs = contribs[contribs['campaign_id'] == campaign_id] if not contribs.empty and 'campaign_id' in contribs.columns else pd.DataFrame()
    raised = float(pd.to_numeric(camp_contribs['amount'], errors='coerce').fillna(0).sum()) if not camp_contribs.empty else 0
    my_contribs = camp_contribs[camp_contribs['member_id'] == session['member_id']] if not camp_contribs.empty else pd.DataFrame()
    my_amount = float(pd.to_numeric(my_contribs['amount'], errors='coerce').fillna(0).sum()) if not my_contribs.empty else 0
    pct = min((raised / target * 100) if target else 0, 100)

    content = render_template_string(r"""
<div class="form-container">
    <h1>🎯 {{ c.title }}</h1>
    <p class="form-subtitle">{{ c.description }}</p>

    <div style="background:var(--presec-blue-pale);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem;text-align:center;">
        <div style="font-size:2rem;font-weight:800;color:var(--presec-blue);">GH₵{{ "%.2f"|format(raised) }}</div>
        <div style="color:var(--gray-500);font-size:0.9rem;">raised of GH₵{{ "%.2f"|format(target) }}</div>
        <div class="progress-track" style="margin-top:0.75rem;">
            <div class="progress-fill {% if pct >= 100 %}full{% endif %}" style="width:{{ pct }}%"></div>
        </div>
        <div style="font-size:0.85rem;color:var(--gray-500);margin-top:0.5rem;">{{ pct|round(1) }}% funded</div>
        {% if my_amount > 0 %}
        <div style="margin-top:0.5rem;color:#16a34a;font-weight:700;">✓ You've contributed GH₵{{ "%.2f"|format(my_amount) }}</div>
        {% endif %}
    </div>

    <form method="POST">
        """ + CSRF_INPUT + r"""
        <div class="form-group">
            <label for="amount">Amount (GH₵) *</label>
            <input type="number" id="amount" name="amount" step="0.01" min="1" required placeholder="Enter amount">
        </div>
        <div class="form-group">
            <label for="method">Payment Method *</label>
            <select id="method" name="method" required>
                <option value="">Select method</option>
                <option>Mobile Money</option>
                <option>Bank Transfer</option>
                <option>Cash</option>
                <option>Card</option>
            </select>
        </div>
        <div class="form-group">
            <label for="note">Note (Optional)</label>
            <textarea id="note" name="note" rows="2" placeholder="Payment reference or message"></textarea>
        </div>
        <button type="submit" class="btn btn-primary btn-full">💸 Contribute</button>
    </form>
    <p class="form-footer"><a href="{{ url_for('campaigns_index') }}">← Back to Campaigns</a></p>
</div>
""", c=c, raised=raised, target=target, pct=pct, my_amount=my_amount)
    return render_page(content)


# =============================================================
# DUES
# =============================================================
@app.route('/dues')
@login_required
def dues_index():
    dues_campaigns = load_dues_campaigns()
    dues = load_dues()

    items = []
    if not dues_campaigns.empty:
        for _, d in dues_campaigns.iterrows():
            if str(d.get('active', True)).lower() not in ['true','1','yes']:
                continue
            did = d['dues_id']
            amount = float(d.get('amount', 0) or 0)
            my_payments = dues[(dues['dues_id'] == did) & (dues['member_id'] == session['member_id'])] if not dues.empty and 'dues_id' in dues.columns else pd.DataFrame()
            my_paid = float(pd.to_numeric(my_payments['amount'], errors='coerce').fillna(0).sum()) if not my_payments.empty else 0
            items.append({
                'dues_id': did, 'month': d.get('month',''), 'year': d.get('year',''),
                'amount': amount, 'my_paid': my_paid
            })

    content = render_template_string(r"""
<div class="reports-header">
    <div>
        <h1>📅 Monthly Dues</h1>
        <p class="subtitle">Pay your monthly dues for the year group</p>
    </div>
    <div class="report-actions">
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a>
    </div>
</div>

{% if items %}
<div class="polls-grid">
    {% for d in items %}
    <div class="poll-card">
        <h3>{{ d.month }} {{ d.year }}</h3>
        <p>Monthly dues: GH₵{{ "%.2f"|format(d.amount) }}</p>
        {% if d.my_paid >= d.amount %}
            <span class="voted-badge">✓ Paid — GH₵{{ "%.2f"|format(d.my_paid) }}</span>
        {% elif d.my_paid > 0 %}
            <p style="color:#ed8f00;font-weight:700;">Partial: GH₵{{ "%.2f"|format(d.my_paid) }} of GH₵{{ "%.2f"|format(d.amount) }}</p>
            <a href="{{ url_for('dues_pay', dues_id=d.dues_id) }}" class="btn btn-primary">Pay Remaining</a>
        {% else %}
            <a href="{{ url_for('dues_pay', dues_id=d.dues_id) }}" class="btn btn-primary">💸 Pay Now</a>
        {% endif %}
    </div>
    {% endfor %}
</div>
{% else %}
<div class="recent-section">
    <h2>No open dues</h2>
    <p class="empty-state">Check back later.</p>
</div>
{% endif %}
""", items=items)
    return render_page(content)


@app.route('/dues/<dues_id>/pay', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per hour")
def dues_pay(dues_id):
    dues_campaigns = load_dues_campaigns()
    if dues_campaigns.empty:
        flash('Dues not found.', 'danger'); return redirect(url_for('dues_index'))
    row = dues_campaigns[dues_campaigns['dues_id'] == dues_id]
    if row.empty:
        flash('Dues not found.', 'danger'); return redirect(url_for('dues_index'))
    d = row.iloc[0].to_dict()
    amount = float(d.get('amount', 0) or 0)

    if request.method == 'POST':
        try:
            amt = float(request.form.get('amount', '0') or 0)
        except ValueError:
            amt = 0
        if amt <= 0:
            flash('Please enter a valid amount.', 'danger'); return redirect(url_for('dues_pay', dues_id=dues_id))
        append_row(DUES_FILE, {
            'payment_id': f"DUESPAY{int(time.time())}_{random.randint(100, 999)}",
            'dues_id': dues_id,
            'month': d.get('month',''),
            'year': d.get('year',''),
            'member_id': session['member_id'],
            'member_name': session['member_name'],
            'amount': amt,
            'method': request.form.get('method', ''),
            'note': request.form.get('note', '').strip(),
            'created_at': datetime.now().isoformat()
        }, sb_table='dues')
        flash(f'Thank you! GH₵{amt:.2f} paid for {d.get("month","")} {d.get("year","")} dues.', 'success')
        return redirect(url_for('dues_index'))

    dues = load_dues()
    my_payments = dues[(dues['dues_id'] == dues_id) & (dues['member_id'] == session['member_id'])] if not dues.empty and 'dues_id' in dues.columns else pd.DataFrame()
    my_paid = float(pd.to_numeric(my_payments['amount'], errors='coerce').fillna(0).sum()) if not my_payments.empty else 0
    remaining = max(amount - my_paid, 0)

    content = render_template_string(r"""
<div class="form-container">
    <h1>📅 {{ d.month }} {{ d.year }} Dues</h1>
    <p class="form-subtitle">GH₵{{ "%.2f"|format(amount) }} per member</p>

    <div style="background:var(--presec-blue-pale);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem;text-align:center;">
        <div style="font-size:1.1rem;color:var(--gray-500);">Already paid</div>
        <div style="font-size:2rem;font-weight:800;color:var(--presec-blue);">GH₵{{ "%.2f"|format(my_paid) }}</div>
        <div style="margin-top:0.5rem;font-weight:700;color:{{ '#16a34a' if remaining == 0 else '#ed1c24' }};">
            {{ '✓ Fully paid' if remaining == 0 else 'Remaining: GH₵' + "%.2f"|format(remaining) }}
        </div>
    </div>

    <form method="POST">
        """ + CSRF_INPUT + r"""
        <div class="form-group">
            <label for="amount">Amount (GH₵) *</label>
            <input type="number" id="amount" name="amount" step="0.01" min="1" value="{{ '%.2f'|format(remaining) if remaining > 0 else '' }}" required>
        </div>
        <div class="form-group">
            <label for="method">Payment Method *</label>
            <select id="method" name="method" required>
                <option value="">Select method</option>
                <option>Mobile Money</option>
                <option>Bank Transfer</option>
                <option>Cash</option>
                <option>Card</option>
            </select>
        </div>
        <div class="form-group">
            <label for="note">Note (Optional)</label>
            <textarea id="note" name="note" rows="2" placeholder="Reference or message"></textarea>
        </div>
        <button type="submit" class="btn btn-primary btn-full">💸 Pay Dues</button>
    </form>
    <p class="form-footer"><a href="{{ url_for('dues_index') }}">← Back to Dues</a></p>
</div>
""", d=d, amount=amount, my_paid=my_paid, remaining=remaining)
    return render_page(content)


# =============================================================
# VOTING
# =============================================================
@app.route('/vote')
@login_required
def vote_index():
    polls = load_polls()
    items = []
    if not polls.empty:
        for _, p in polls.iterrows():
            if str(p.get('active', True)).lower() not in ['true','1','yes']:
                continue
            pdict = p.to_dict()
            pdict['has_voted'] = has_voted(session['member_id'], p['poll_id'])
            items.append(pdict)
    content = render_template_string(r"""
<div class="reports-header">
    <div><h1>🗳️ Voting Center</h1><p class="subtitle">Cast your vote</p></div>
    <div class="report-actions"><a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a></div>
</div>
{% if items %}
<div class="polls-grid">
    {% for p in items %}
    <div class="poll-card">
        <h3>{{ p.title }}</h3>
        <p>{{ p.description }}</p>
        {% if p.has_voted %}<span class="voted-badge">✓ Voted</span>
        {% else %}<a href="{{ url_for('vote', poll_id=p.poll_id) }}" class="btn btn-primary">🗳️ Vote</a>{% endif %}
    </div>
    {% endfor %}
</div>
{% else %}<p class="empty-state">No open polls.</p>{% endif %}
""", items=items)
    return render_page(content)


@app.route('/vote/<poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    polls = load_polls()
    row = polls[polls['poll_id'] == poll_id] if not polls.empty else pd.DataFrame()
    if row.empty:
        flash('Poll not found.', 'danger'); return redirect(url_for('vote_index'))
    p = row.iloc[0].to_dict()
    try:
        options = json.loads(p.get('options_json', '[]'))
    except Exception:
        options = []
    if has_voted(session['member_id'], poll_id):
        flash('You already voted.', 'info'); return redirect(url_for('vote_index'))
    if request.method == 'POST':
        opt = request.form.get('option_id', '')
        if not opt:
            flash('Select an option.', 'danger'); return redirect(url_for('vote', poll_id=poll_id))
        append_row(VOTES_FILE, {
            'vote_id': f"VOT{int(time.time())}_{random.randint(100, 999)}",
            'poll_id': poll_id,
            'member_id': session['member_id'],
            'member_name': session['member_name'],
            'option_id': opt,
            'voted_at': datetime.now().isoformat()
        }, sb_table='votes')
        flash('Vote recorded!', 'success')
        return redirect(url_for('vote_index'))
    content = render_template_string(r"""
<div class="form-container">
    <h1>{{ p.title }}</h1>
    <p class="form-subtitle">{{ p.description }}</p>
    <form method="POST">
        """ + CSRF_INPUT + r"""
        <div class="vote-options">
            {% for o in options %}
            <label class="vote-option">
                <input type="radio" name="option_id" value="{{ o.id }}" required>
                <span class="option-text">{{ o.text }}</span>
            </label>
            {% endfor %}
        </div>
        <button type="submit" class="btn btn-primary btn-full">🗳️ Cast Vote</button>
    </form>
</div>
""", p=p, options=options)
    return render_page(content)


# =============================================================
# MEMBERS & GALLERY
# =============================================================
@app.route('/members')
@login_required
def members():
    df = load_members()
    lst = df[['member_id','full_name','house','occupation','location','photo_filename']].to_dict('records') if not df.empty else []
    content = render_template_string(r"""
<div class="recent-section">
    <h2>👥 Member Directory</h2>
    {% if members %}
    <div class="polls-grid">
        {% for m in members %}
        <a href="{{ url_for('member_profile', member_id=m.member_id) }}" class="poll-card" style="text-decoration:none;color:inherit;">
            <div style="display:flex;align-items:center;gap:1rem;">
                {% if m.photo_filename %}
                <img src="{{ m.photo_filename if m.photo_filename.startswith('http') else url_for('static', filename='uploads/' + m.photo_filename) }}" style="width:60px;height:60px;border-radius:50%;object-fit:cover;border:2px solid var(--presec-blue);">
                {% else %}
                <div class="member-photo-placeholder" style="width:60px;height:60px;font-size:1.5rem;">{{ m.full_name[0] }}</div>
                {% endif %}
                <div>
                    <h3 style="margin:0;">{{ m.full_name }}</h3>
                    <p style="margin:0.25rem 0 0;font-size:0.85rem;">{{ m.house or 'Odadeɛ' }} • {{ m.location or '—' }}</p>
                </div>
            </div>
        </a>
        {% endfor %}
    </div>
    {% else %}<p class="empty-state">No members.</p>{% endif %}
</div>
""", members=lst)
    return render_page(content)


@app.route('/member/<member_id>')
@login_required
def member_profile(member_id):
    m = get_member_by_id(member_id)
    if not m:
        flash('Not found.', 'danger'); return redirect(url_for('members'))
    safe = {k: v for k, v in m.items() if k not in ['password_hash','email']}
    content = render_template_string(r"""
<div class="form-container">
    <div style="text-align:center;">
        {% if member.photo_filename %}
        <img src="{{ member.photo_filename if member.photo_filename.startswith('http') else url_for('static', filename='uploads/' + member.photo_filename) }}" style="width:140px;height:140px;border-radius:50%;object-fit:cover;border:4px solid var(--presec-blue);">
        {% else %}
        <div class="member-photo-placeholder" style="width:140px;height:140px;font-size:3rem;margin:0 auto;">{{ member.full_name[0] }}</div>
        {% endif %}
        <h1 style="color:var(--presec-blue);margin-top:1rem;">{{ member.full_name }}</h1>
        <p style="color:var(--gray-500);">{{ member.house or 'Odadeɛ' }} House</p>
    </div>
    <div style="margin-top:2rem;">
        <p><strong>Occupation:</strong> {{ member.occupation or '—' }}</p>
        <p><strong>Location:</strong> {{ member.location or '—' }}</p>
        <p><strong>Bio:</strong> {{ member.bio or '—' }}</p>
        <p><strong>Registered:</strong> {{ member.registered_at[:10] }}</p>
    </div>
    <div style="margin-top:2rem;"><a href="{{ url_for('members') }}" class="btn btn-secondary">← Back</a></div>
</div>
""", member=safe)
    return render_page(content)


@app.route('/gallery')
@login_required
def gallery():
    df = load_gallery()
    items = df.sort_values('uploaded_at', ascending=False).to_dict('records') if not df.empty else []
    content = render_template_string(r"""
<div class="reports-header">
    <div><h1>🖼️ Gallery</h1><p class="subtitle">Memories from 2007</p></div>
    <div class="report-actions">
        <a href="{{ url_for('gallery_upload') }}" class="btn btn-primary">➕ Upload</a>
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">← Dashboard</a>
    </div>
</div>
{% if items %}
<div class="gallery-grid">
    {% for item in items %}
    <div class="gallery-item">
        {% set img_src = item.filename if item.filename.startswith('http') else url_for('static', filename='gallery/' + item.filename) %}
        <a href="{{ img_src }}" target="_blank">
            <img src="{{ img_src }}" loading="lazy">
        </a>
        <div class="gallery-info">
            {% if item.caption %}<p class="gallery-caption">{{ item.caption }}</p>{% endif %}
            <p class="gallery-meta"><span>👤 {{ item.member_name }}</span><span>📅 {{ item.uploaded_at[:10] }}</span></p>
        </div>
    </div>
    {% endfor %}
</div>
{% else %}<p class="empty-state">No photos yet.</p>{% endif %}
""", items=items)
    return render_page(content)


@app.route('/gallery/upload', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per hour")
def gallery_upload():
    if request.method == 'POST':
        caption = request.form.get('caption', '').strip()
        files = request.files.getlist('photos')
        saved = 0
        for photo in files:
            if not photo or not photo.filename: continue
            ext = os.path.splitext(photo.filename)[1].lower()
            if ext not in ['.jpg','.jpeg','.png','.gif','.webp']: continue
            stored = save_upload(
                photo, app.config['GALLERY_FOLDER'],
                f"GAL{int(time.time())}_{random.randint(1000,9999)}"
            )
            if not stored:
                continue
            append_row(GALLERY_FILE, {
                'gallery_id': f"GAL{int(time.time())}_{random.randint(100,999)}",
                'filename': stored, 'caption': caption,
                'member_id': session['member_id'],
                'member_name': session['member_name'],
                'uploaded_at': datetime.now().isoformat()
            }, sb_table='gallery')
            saved += 1
        if saved:
            flash(f'{saved} photo(s) uploaded!', 'success'); return redirect(url_for('gallery'))
        flash('No valid images.', 'danger'); return redirect(url_for('gallery_upload'))
    content = render_template_string(r"""
<div class="form-container">
    <h1>🖼️ Upload Photos</h1>
    <form method="POST" enctype="multipart/form-data">
        """ + CSRF_INPUT + r"""
        <div class="form-group">
            <label>Select Photos *</label>
            <input type="file" name="photos" accept="image/*" multiple required class="file-input">
        </div>
        <div class="form-group">
            <label>Caption</label>
            <input type="text" name="caption" maxlength="200" placeholder="Reunion 2025">
        </div>
        <button type="submit" class="btn btn-primary btn-full">⬆️ Upload</button>
    </form>
    <p class="form-footer"><a href="{{ url_for('gallery') }}">← Back</a></p>
</div>
""")
    return render_page(content)


# =============================================================
# ADMIN (in main app — minimal, full admin is separate)
# =============================================================
@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == 'POST':
        if request.form.get('password', '') == ADMIN_PASSWORD:
            session['is_admin'] = True
            flash('Admin access granted.', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Incorrect password.', 'danger')
    content = render_template_string(r"""
<div class="form-container">
    <h1>Admin Access</h1>
    <form method="POST">""" + CSRF_INPUT + r"""
        <div class="form-group"><label>Password</label><input type="password" name="password" required autofocus></div>
        <button type="submit" class="btn btn-primary btn-full">🔓 Enter</button>
    </form>
</div>""")
    return render_page(content)


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Admin logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    content = render_template_string("""
<div class="reports-header">
    <div><h1>Admin Dashboard</h1><p class="subtitle">Use the standalone admin panel at :5001 for full control</p></div>
    <div class="report-actions"><a href="/admin/logout" class="btn btn-secondary">Logout</a></div>
</div>
<p style="text-align:center;padding:2rem;">For the full admin experience, run <code>admin_app.py</code> on port 5001.</p>
""")
    return render_page(content)


# =============================================================
# ERROR HANDLERS
# =============================================================
@app.errorhandler(404)
def not_found(e):
    content = render_template_string('<div class="form-container" style="text-align:center;"><h1>404</h1><p>Page not found.</p><a href="{{ url_for(\'index\') }}" class="btn btn-primary btn-full">Home</a></div>')
    return render_page(content), 404


@app.errorhandler(500)
def server_error(e):
    content = render_template_string('<div class="form-container" style="text-align:center;"><h1>⚠️</h1><p>Something went wrong.</p><a href="{{ url_for(\'index\') }}" class="btn btn-primary btn-full">Home</a></div>')
    return render_page(content), 500


# =============================================================
# DIAGNOSTICS
# =============================================================
@app.route('/check-files')
def check_files():
    return jsonify({
        'base_dir': BASE_DIR,
        'https_enabled': HTTPS_ENABLED,
        'certs_present': CERTS_PRESENT,
        'behind_proxy': BEHIND_PROXY,
        'use_supabase': USE_SUPABASE,
        'use_imgbb': USE_IMGBB,
        'supabase_url_set': bool(SUPABASE_URL),
        'imgbb_key_set': bool(IMGBB_API_KEY),
        'cert_file': CERT_FILE,
        'key_file': KEY_FILE,
        'data_dir': DATA_DIR,
    })


@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'https_enabled': HTTPS_ENABLED,
        'certs_present': CERTS_PRESENT,
        'use_supabase': USE_SUPABASE,
        'use_imgbb': USE_IMGBB,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='images/presec-badge.png'))


# =============================================================
# MAIN — HTTPS-aware + cloud-aware
# =============================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))

    print("\n" + "=" * 60)
    print("🏫 ODADEAƐ07 - PRESEC 2007 YEAR GROUP")
    print("=" * 60)
    print(f"🔒 HTTPS: {'enabled' if HTTPS_ENABLED else 'disabled'}")
    print(f"🌐 Mode:  {'CLOUD (behind proxy)' if BEHIND_PROXY else 'LOCAL'}")
    print(f"📊 Data:  {'Supabase' if USE_SUPABASE else 'CSV (local)'}")
    print(f"🖼️  Images: {'ImgBB (cloud)' if USE_IMGBB else 'Local filesystem'}")
    print(f"🔑 Admin password: {ADMIN_PASSWORD}")
    print(f"📁 Base dir: {BASE_DIR}")
    print("=" * 60)

    # In cloud, Gunicorn runs the app — this block only runs locally
    if BEHIND_PROXY:
        app.run(debug=False, host='0.0.0.0', port=port)
    elif CERTS_PRESENT:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        print("🔐 Running HTTPS at https://localhost:5000")
        print("=" * 60)
        app.run(debug=False, host='0.0.0.0', port=port, ssl_context=ctx)
    else:
        print("🌐 Running HTTP at http://localhost:5000")
        print("   For HTTPS, run: mkcert localhost 127.0.0.1 ::1")
        print("=" * 60)
        app.run(debug=False, host='0.0.0.0', port=port)