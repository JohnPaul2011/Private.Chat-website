import sys, os

# ── Platform Autodetection: 'threading' on Windows, 'gevent' on Linux/Unix ──
IS_WINDOWS = sys.platform.startswith("win")
ASYNC_MODE = "threading"

if not IS_WINDOWS:
    try:
        from gevent import monkey
        monkey.patch_all()
        ASYNC_MODE = "gevent"
    except ImportError:
        ASYNC_MODE = "threading"

from flask import render_template, Flask, request, redirect, session, url_for, flash, jsonify, abort
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from colorama import init as init_color
from pywebpush import webpush, WebPushException
from authlib.integrations.flask_client import OAuth
import time, logging, re, hmac, hashlib, secrets, base64, struct, datetime, threading, uuid, json
import requests as _requests
import sqlite3 as _sqlite3

init_color(convert=True, strip=False)
logging.basicConfig(level=logging.INFO)
logging.info(f"Platform detected: {'Windows' if IS_WINDOWS else 'Linux/Unix'} -> Socket.IO async_mode='{ASYNC_MODE}'")

app = Flask(__name__)
PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))
if PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=PROXY_HOPS, x_proto=1, x_host=0)

def _load_secret_key():
    env_secret = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET")
    if env_secret:
        return env_secret.strip()
    secret_path = os.path.join(os.path.dirname(__file__), ".session_secret")
    if os.path.exists(secret_path):
        try:
            with open(secret_path, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val:
                    return val
        except Exception:
            pass
    new_secret = secrets.token_hex(32)
    try:
        with open(secret_path, "w", encoding="utf-8") as f:
            f.write(new_secret)
    except Exception:
        pass
    return new_secret

app.secret_key = _load_secret_key()
app.config['SECRET_KEY'] = app.secret_key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("FORCE_HTTPS", "0") == "1"
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
socketio = SocketIO(app, async_mode=ASYNC_MODE, logger=False, engineio_logger=False, cors_allowed_origins=[])
                    ping_timeout=10, ping_interval=8)

# ── Google OAuth ──
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
oauth = OAuth(app)
google_oauth = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ── WebPush ──
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_CLAIMS = {"sub": "mailto:admin@example.com"}
push_subscriptions = {}  # {google_id: subscription_dict}

# ── Security ──
BAD_USERNAMES = {"admin", "server", "system", "moderator", "host"}
_state_lock = threading.Lock()
_login_attempts = {}
LOGIN_MAX, LOGIN_WINDOW, LOGIN_LOCKOUT = 5, 300, 900
_used_totp_codes = {}
_msg_counters = {}
RATE_LIMIT_WINDOW, RATE_LIMIT_MAX = 5, 15

# ── Admin ──
ADMIN_PASSWORD_HASH = os.environ.get(
    "ADMIN_PASSWORD_HASH",
    generate_password_hash(os.environ.get("ADMIN_PASSWORD", "changeme"))
)
TOTP_SECRET = os.environ.get("TOTP_SECRET", "")
ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "").split(",") if os.environ.get("ADMIN_EMAILS") else []

# ── Supabase (friends storage) ──
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

def _supabase_headers():
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
    }

def supabase_available():
    return bool(SUPABASE_URL and SUPABASE_SERVICE_KEY)


# ── Local SQLite Fallback Database ──
LOCAL_DB_PATH = os.environ.get("LOCAL_DB_PATH", os.path.join(os.path.dirname(__file__), "local_chat.db"))
_local_db = None
_local_db_lock = threading.Lock()

def _get_local_db():
    """Get or create local SQLite database connection."""
    global _local_db
    if _local_db is None:
        with _local_db_lock:
            if _local_db is None:
                _local_db = _sqlite3.connect(LOCAL_DB_PATH, check_same_thread=False)
                _local_db.row_factory = _sqlite3.Row
                _init_local_db(_local_db)
    return _local_db

def _init_local_db(conn):
    """Initialize local SQLite database with required tables."""
    cursor = conn.cursor()
    
    # chat_profiles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_profiles (
            google_id TEXT PRIMARY KEY,
            email TEXT,
            display_name TEXT,
            public_key TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # chat_friends
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_google_id TEXT NOT NULL,
            owner_email TEXT,
            friend_google_id TEXT,
            friend_email TEXT,
            friend_display_name TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(owner_google_id, friend_google_id)
        )
    """)
    
    # chat_friend_requests
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_friend_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_google_id TEXT NOT NULL,
            sender_email TEXT,
            recipient_google_id TEXT,
            recipient_email TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            responded_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # chat_notifications
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_google_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT,
            room_code TEXT,
            read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # chat_direct_messages
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_direct_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dm_room TEXT NOT NULL,
            sender_google_id TEXT NOT NULL,
            sender_name TEXT,
            recipient_google_id TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'text',
            ciphertext TEXT,
            client_id TEXT,
            reply_to TEXT,
            mime TEXT,
            duration REAL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            synced INTEGER NOT NULL DEFAULT 0
        )
    """)
    
    # chat_announcements - admin announcements
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # pending_sync - messages to sync to Supabase when it comes back
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_sync (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            action TEXT NOT NULL DEFAULT 'insert',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            attempts INTEGER NOT NULL DEFAULT 0
        )
    """)
    
    conn.commit()

def local_db_available():
    """Check if local database is available."""
    try:
        conn = _get_local_db()
        conn.execute("SELECT 1")
        return True
    except Exception:
        return False


# ── Database Status Check ──
DB_STATUS = {"ok": True, "last_check": 0, "last_error": None}
DB_CHECK_INTERVAL = 60  # seconds

def check_db_status():
    """Check if Supabase is accessible and update status."""
    global DB_STATUS
    now = time.time()
    if now - DB_STATUS["last_check"] < DB_CHECK_INTERVAL:
        return DB_STATUS["ok"]
    
    DB_STATUS["last_check"] = now
    if not supabase_available():
        DB_STATUS["ok"] = False
        DB_STATUS["last_error"] = "Supabase not configured"
        return False
    
    try:
        r = _requests.get(
            f"{SUPABASE_URL}/rest/v1/",
            headers=_supabase_headers(),
            timeout=5,
        )
        if r.status_code < 500:
            DB_STATUS["ok"] = True
            DB_STATUS["last_error"] = None
            return True
        else:
            DB_STATUS["ok"] = False
            DB_STATUS["last_error"] = f"HTTP {r.status_code}"
            return False
    except Exception as e:
        DB_STATUS["ok"] = False
        DB_STATUS["last_error"] = "Connection failed"
        return False


def get_db_status():
    """Get current database status for client alerts."""
    check_db_status()  # Ensure fresh check
    return {
        "ok": DB_STATUS["ok"],
        "error": DB_STATUS["last_error"],
        "configured": supabase_available()
    }

# ── Helper Functions ──
def email_to_name(email):
    if not email or "@" not in email:
        return email or ""
    local = email.split("@")[0]
    cleaned = " ".join(part.capitalize() for part in re.split(r"[._\-+]", local) if part)
    return cleaned or local

def send_push(google_id, title, body, data=None):
    if not google_id or not VAPID_PRIVATE_KEY:
        return
    with _state_lock:
        sub = push_subscriptions.get(google_id)
    if not sub:
        return
    try:
        payload = {"title": title, "body": body}
        if data:
            payload["data"] = data
        webpush(
            subscription_info=sub,
            data=json.dumps(payload),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims=dict(VAPID_CLAIMS),
        )
    except WebPushException as e:
        logging.info(f"Push failed, dropping subscription: {e}")
        with _state_lock:
            push_subscriptions.pop(google_id, None)

def client_ip():
    return request.remote_addr or "unknown"

def check_lockout(key):
    with _state_lock:
        rec = _login_attempts.get(key)
        return bool(rec and rec["locked_until"] > time.time())

def record_failure(key):
    with _state_lock:
        now = time.time()
        rec = _login_attempts.setdefault(key, {"fails": [], "locked_until": 0})
        rec["fails"] = [t for t in rec["fails"] if now - t < LOGIN_WINDOW]
        rec["fails"].append(now)
        if len(rec["fails"]) >= LOGIN_MAX:
            rec["locked_until"] = now + LOGIN_LOCKOUT
            rec["fails"] = []

def record_success(key):
    with _state_lock:
        _login_attempts.pop(key, None)

def require_admin():
    # Auto-login as admin if user's email is in ADMIN_EMAILS
    if session.get("is_admin"):
        return
    
    # Check if logged-in user's email is in admin list
    user_email = session.get("google_email", "")
    if user_email and user_email in ADMIN_EMAILS:
        session.permanent = True
        session["is_admin"] = True
        return
    
    # Otherwise require explicit admin login
    if not session.get("is_admin"):
        abort(403)

def check_csrf():
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or token != session.get("csrf_token"):
        abort(403)

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = get_csrf_token

def rate_limited(name):
    with _state_lock:
        now = time.time()
        bucket = _msg_counters.setdefault(name, [])
        bucket[:] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
        if len(bucket) >= RATE_LIMIT_MAX:
            return True
        bucket.append(now)
        return False

def totp_now(secret, step=30, digits=6, t=None):
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    counter = int((t or time.time()) // step)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

def verify_totp(secret, code):
    if not code or not re.match(r"^\d{6}$", code):
        return False
    now = time.time()
    with _state_lock:
        for k, exp in list(_used_totp_codes.items()):
            if exp < now:
                _used_totp_codes.pop(k, None)
        for skew in (-1, 0, 1):
            candidate = totp_now(secret, t=now + skew * 30)
            if hmac.compare_digest(candidate, code):
                if code in _used_totp_codes:
                    return False
                _used_totp_codes[code] = now + 90
                return True
    return False


# ── Supabase Functions for Friends & DMs ──
def sb_list_friends(owner_google_id):
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_friends",
                headers=_supabase_headers(),
                params={"owner_google_id": f"eq.{owner_google_id}", "order": "created_at.desc"},
                timeout=8,
            )
            r.raise_for_status()
            rows = r.json()
            for f in rows:
                if not f.get("friend_google_id") and f.get("friend_email"):
                    fgid = sb_find_user_by_email(f["friend_email"])
                    if fgid:
                        f["friend_google_id"] = fgid
                if not f.get("friend_display_name"):
                    if f.get("friend_google_id"):
                        prof = sb_get_profile(f["friend_google_id"])
                        if prof and prof.get("display_name"):
                            f["friend_display_name"] = prof["display_name"]
                if not f.get("friend_display_name") and f.get("friend_email"):
                    f["friend_display_name"] = email_to_name(f["friend_email"])
            return rows
        except Exception as e:
            logging.info(f"Supabase list_friends failed, falling back to local: {e}")
    
    # Fallback to local SQLite
    return lb_list_friends(owner_google_id)

def sb_add_friend(owner_google_id, owner_email, friend_google_id, friend_email, friend_display_name):
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.post(
                f"{SUPABASE_URL}/rest/v1/chat_friends",
                headers={**_supabase_headers(), "Prefer": "resolution=merge-duplicates"},
                json={
                    "owner_google_id": owner_google_id,
                    "owner_email": owner_email,
                    "friend_google_id": friend_google_id,
                    "friend_email": friend_email,
                    "friend_display_name": friend_display_name,
                },
                timeout=8,
            )
            if r.status_code < 400:
                return True, None
        except Exception as e:
            logging.info(f"Supabase add_friend failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_add_friend(owner_google_id, owner_email, friend_google_id, friend_email, friend_display_name)

def sb_remove_friend(owner_google_id, friend_google_id):
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.delete(
                f"{SUPABASE_URL}/rest/v1/chat_friends",
                headers=_supabase_headers(),
                params={"owner_google_id": f"eq.{owner_google_id}", "friend_google_id": f"eq.{friend_google_id}"},
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase remove_friend failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_remove_friend(owner_google_id, friend_google_id)

def sb_find_user_by_email(email):
    if not email:
        return None
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_profiles",
                headers=_supabase_headers(),
                params={"email": f"eq.{email}", "limit": 1},
                timeout=8,
            )
            r.raise_for_status()
            rows = r.json()
            if rows:
                return rows[0]["google_id"]
        except Exception as e:
            logging.info(f"Supabase find_user_by_email (profiles) failed: {e}")
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_friends",
                headers=_supabase_headers(),
                params={"friend_email": f"eq.{email}", "limit": 1},
                timeout=8,
            )
            r.raise_for_status()
            rows = r.json()
            if rows:
                return rows[0]["friend_google_id"]
        except Exception as e:
            logging.info(f"Supabase find_user_by_email (friends) failed: {e}")
    
    # Fallback to local
    return lb_find_user_by_email(email)

def sb_get_profile(google_id):
    if not google_id:
        return None
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_profiles",
                headers=_supabase_headers(),
                params={"google_id": f"eq.{google_id}", "limit": 1},
                timeout=8,
            )
            r.raise_for_status()
            rows = r.json()
            if rows:
                return rows[0]
        except Exception as e:
            logging.info(f"Supabase get_profile failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_get_profile(google_id)

def sb_upsert_profile(google_id, email, display_name):
    if not google_id:
        return False, "No Google ID"
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.post(
                f"{SUPABASE_URL}/rest/v1/chat_profiles",
                headers={**_supabase_headers(), "Prefer": "resolution=merge-duplicates"},
                json={
                    "google_id": google_id,
                    "email": email,
                    "display_name": display_name,
                    "updated_at": datetime.datetime.utcnow().isoformat(),
                },
                timeout=8,
            )
            if r.status_code < 400:
                return True, None
        except Exception as e:
            logging.info(f"Supabase upsert_profile failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_upsert_profile(google_id, email, display_name)

def sb_set_public_key(google_id, public_key_b64):
    if not google_id or not public_key_b64:
        return False
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.post(
                f"{SUPABASE_URL}/rest/v1/chat_profiles",
                headers={**_supabase_headers(), "Prefer": "resolution=merge-duplicates"},
                json={
                    "google_id": google_id,
                    "public_key": public_key_b64,
                    "updated_at": datetime.datetime.utcnow().isoformat(),
                },
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase set_public_key failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_set_public_key(google_id, public_key_b64)

def sb_get_public_key(google_id):
    prof = sb_get_profile(google_id)
    return (prof or {}).get("public_key")

def sb_is_friend(owner_google_id, other_google_id):
    if not owner_google_id or not other_google_id:
        return False
    if str(owner_google_id) == str(other_google_id):
        return False
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_friends",
                headers=_supabase_headers(),
                params={
                    "owner_google_id": f"eq.{owner_google_id}",
                    "friend_google_id": f"eq.{other_google_id}",
                    "limit": 1,
                },
                timeout=8,
            )
            r.raise_for_status()
            if r.json():
                return True
        except Exception as e:
            logging.info(f"Supabase is_friend check failed: {e}")
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_friends",
                headers=_supabase_headers(),
                params={
                    "owner_google_id": f"eq.{other_google_id}",
                    "friend_google_id": f"eq.{owner_google_id}",
                    "limit": 1,
                },
                timeout=8,
            )
            r.raise_for_status()
            if r.json():
                return True
        except Exception as e:
            logging.info(f"Supabase is_friend reverse check failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_is_friend(owner_google_id, other_google_id)

def sb_save_direct_message(dm_room, sender_gid, sender_name, recipient_gid, mtype, ciphertext,
                            client_id=None, reply_to=None, mime=None, duration=None):
    if not dm_room or not sender_gid or not recipient_gid:
        return False
    
    # Try Supabase first
    if supabase_available():
        try:
            payload = {
                "dm_room": dm_room,
                "sender_google_id": sender_gid,
                "sender_name": sender_name,
                "recipient_google_id": recipient_gid,
                "type": mtype,
                "ciphertext": ciphertext,
                "client_id": client_id,
                "reply_to": reply_to,
                "mime": mime,
                "duration": duration,
            }
            r = _requests.post(
                f"{SUPABASE_URL}/rest/v1/chat_direct_messages",
                headers=_supabase_headers(),
                json=payload,
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase save_direct_message failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_save_direct_message(dm_room, sender_gid, sender_name, recipient_gid, mtype, ciphertext,
                                  client_id, reply_to, mime, duration)

def sb_list_direct_messages(dm_room, limit=100):
    if not dm_room:
        return []
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_direct_messages",
                headers=_supabase_headers(),
                params={
                    "dm_room": f"eq.{dm_room}",
                    "order": "created_at.asc",
                    "limit": limit,
                },
                timeout=8,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logging.info(f"Supabase list_direct_messages failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_list_direct_messages(dm_room, limit)


# ── Friend Requests ──
def sb_create_friend_request(sender_gid, sender_email, recipient_email, recipient_gid=None):
    if not sender_gid:
        return False, "No sender Google ID"
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.post(
                f"{SUPABASE_URL}/rest/v1/chat_friend_requests",
                headers=_supabase_headers(),
                json={
                    "sender_google_id": sender_gid,
                    "sender_email": sender_email,
                    "recipient_google_id": recipient_gid,
                    "recipient_email": recipient_email,
                    "status": "pending",
                },
                timeout=8,
            )
            if r.status_code < 400:
                return True, None
            elif r.status_code == 409 or "duplicate" in r.text.lower():
                return False, "You already have a pending request to this person."
            elif "schema cache" in r.text.lower() or "could not find the table" in r.text.lower():
                return False, "Database table 'chat_friend_requests' is not created in Supabase yet."
            else:
                return False, r.text[:200]
        except Exception as e:
            logging.info(f"Supabase create_friend_request failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_create_friend_request(sender_gid, sender_email, recipient_email, recipient_gid)

def sb_list_incoming_requests(recipient_gid, status="pending"):
    if not recipient_gid:
        return []
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_friend_requests",
                headers=_supabase_headers(),
                params={
                    "recipient_google_id": f"eq.{recipient_gid}",
                    "status": f"eq.{status}",
                    "order": "created_at.desc",
                },
                timeout=8,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logging.info(f"Supabase list_incoming_requests failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_list_incoming_requests(recipient_gid, status)

def sb_list_outgoing_requests(sender_gid, status="pending"):
    if not sender_gid:
        return []
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_friend_requests",
                headers=_supabase_headers(),
                params={
                    "sender_google_id": f"eq.{sender_gid}",
                    "status": f"eq.{status}",
                    "order": "created_at.desc",
                },
                timeout=8,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logging.info(f"Supabase list_outgoing_requests failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_list_outgoing_requests(sender_gid, status)

def sb_get_friend_request(request_id):
    if not request_id:
        return None
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_friend_requests",
                headers=_supabase_headers(),
                params={"id": f"eq.{request_id}", "limit": 1},
                timeout=8,
            )
            r.raise_for_status()
            rows = r.json()
            if rows:
                return rows[0]
        except Exception as e:
            logging.info(f"Supabase get_friend_request failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_get_friend_request(request_id)

def sb_respond_friend_request(request_id, status):
    if not request_id:
        return False
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.patch(
                f"{SUPABASE_URL}/rest/v1/chat_friend_requests",
                headers=_supabase_headers(),
                params={"id": f"eq.{request_id}"},
                json={"status": status, "responded_at": datetime.datetime.utcnow().isoformat()},
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase respond_friend_request failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_respond_friend_request(request_id, status)

def sb_cancel_friend_request(request_id, sender_gid):
    if not request_id:
        return False
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.delete(
                f"{SUPABASE_URL}/rest/v1/chat_friend_requests",
                headers=_supabase_headers(),
                params={"id": f"eq.{request_id}", "sender_google_id": f"eq.{sender_gid}", "status": "eq.pending"},
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase cancel_friend_request failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_cancel_friend_request(request_id, sender_gid)


# ── Notifications ──
def sb_add_notification(owner_google_id, kind, title, body="", room_code=None):
    if not owner_google_id:
        return False
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.post(
                f"{SUPABASE_URL}/rest/v1/chat_notifications",
                headers=_supabase_headers(),
                json={
                    "owner_google_id": owner_google_id,
                    "kind": kind,
                    "title": title[:200],
                    "body": (body or "")[:500],
                    "room_code": room_code,
                },
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase add_notification failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_add_notification(owner_google_id, kind, title, body, room_code)

def sb_list_notifications(owner_google_id, limit=30):
    if not owner_google_id:
        return []
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_notifications",
                headers=_supabase_headers(),
                params={
                    "owner_google_id": f"eq.{owner_google_id}",
                    "order": "created_at.desc",
                    "limit": limit,
                },
                timeout=8,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logging.info(f"Supabase list_notifications failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_list_notifications(owner_google_id, limit)

def sb_unread_notification_count(owner_google_id):
    if not supabase_available() or not owner_google_id:
        return 0
    try:
        r = _requests.get(
            f"{SUPABASE_URL}/rest/v1/chat_notifications",
            headers={**_supabase_headers(), "Prefer": "count=exact"},
            params={"owner_google_id": f"eq.{owner_google_id}", "read": "eq.false", "select": "id"},
            timeout=8,
        )
        r.raise_for_status()
        cr = r.headers.get("Content-Range", "")
        if "/" in cr:
            total = cr.split("/")[-1]
            return int(total) if total.isdigit() else 0
        return len(r.json())
    except Exception as e:
        logging.info(f"Supabase unread_notification_count failed: {e}")
        return 0

def sb_mark_notifications_read(owner_google_id):
    if not owner_google_id:
        return False
    
    # Try Supabase first
    if supabase_available():
        try:
            r = _requests.patch(
                f"{SUPABASE_URL}/rest/v1/chat_notifications",
                headers=_supabase_headers(),
                params={"owner_google_id": f"eq.{owner_google_id}", "read": "eq.false"},
                json={"read": True},
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase mark_notifications_read failed, falling back to local: {e}")
    
    # Fallback to local
    return lb_mark_notifications_read(owner_google_id)


#  Announcement Functions 
def sb_list_announcements(active_only=True):
    if supabase_available():
        try:
            params = {"order": "created_at.desc"}
            if active_only:
                params["is_active"] = "eq.true"
            r = _requests.get(
                f"{SUPABASE_URL}/rest/v1/chat_announcements",
                headers=_supabase_headers(),
                params=params,
                timeout=8,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logging.info(f"Supabase list_announcements failed, falling back to local: {e}")
    return lb_list_announcements(active_only)


def sb_create_announcement(title, content):
    if not title or not content:
        return False, "Title and content required"
    
    if supabase_available():
        try:
            r = _requests.post(
                f"{SUPABASE_URL}/rest/v1/chat_announcements",
                headers=_supabase_headers(),
                json={"title": title, "content": content, "is_active": True},
                timeout=8,
            )
            if r.status_code < 400:
                return True, None
        except Exception as e:
            logging.info(f"Supabase create_announcement failed, falling back to local: {e}")
    
    return lb_create_announcement(title, content)


def sb_delete_announcement(announcement_id):
    if not announcement_id:
        return False
    
    if supabase_available():
        try:
            r = _requests.delete(
                f"{SUPABASE_URL}/rest/v1/chat_announcements",
                headers=_supabase_headers(),
                params={"id": f"eq.{announcement_id}"},
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase delete_announcement failed, falling back to local: {e}")
    
    return lb_delete_announcement(announcement_id)


def sb_toggle_announcement(announcement_id, is_active):
    if not announcement_id:
        return False
    
    if supabase_available():
        try:
            r = _requests.patch(
                f"{SUPABASE_URL}/rest/v1/chat_announcements",
                headers=_supabase_headers(),
                params={"id": f"eq.{announcement_id}"},
                json={"is_active": is_active, "updated_at": datetime.datetime.utcnow().isoformat()},
                timeout=8,
            )
            if r.status_code < 400:
                return True
        except Exception as e:
            logging.info(f"Supabase toggle_announcement failed, falling back to local: {e}")
    
    return lb_toggle_announcement(announcement_id, is_active)



# ── Local Database Functions (Fallback) ──
def lb_list_friends(owner_google_id):
    """Local SQLite fallback for listing friends."""
    if not owner_google_id:
        return []
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM chat_friends WHERE owner_google_id = ? ORDER BY created_at DESC",
            (owner_google_id,)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        for f in rows:
            if not f.get("friend_display_name") and f.get("friend_email"):
                f["friend_display_name"] = email_to_name(f["friend_email"])
        return rows
    except Exception as e:
        logging.info(f"Local DB list_friends failed: {e}")
        return []


def lb_add_friend(owner_google_id, owner_email, friend_google_id, friend_email, friend_display_name):
    """Local SQLite fallback for adding friend."""
    if not owner_google_id:
        return False, "No owner Google ID"
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT OR IGNORE INTO chat_friends 
               (owner_google_id, owner_email, friend_google_id, friend_email, friend_display_name)
               VALUES (?, ?, ?, ?, ?)""",
            (owner_google_id, owner_email, friend_google_id, friend_email, friend_display_name)
        )
        conn.commit()
        
        # Mark for sync to Supabase
        cursor.execute(
            "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
            ("chat_friends", cursor.lastrowid, "insert")
        )
        conn.commit()
        return True, None
    except Exception as e:
        logging.info(f"Local DB add_friend failed: {e}")
        return False, "Database error"


def lb_remove_friend(owner_google_id, friend_google_id):
    """Local SQLite fallback for removing friend."""
    if not owner_google_id or not friend_google_id:
        return False
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM chat_friends WHERE owner_google_id = ? AND friend_google_id = ?",
            (owner_google_id, friend_google_id)
        )
        conn.commit()
        
        if cursor.rowcount > 0:
            cursor.execute(
                "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
                ("chat_friends", friend_google_id, "delete")
            )
            conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB remove_friend failed: {e}")
        return False


def lb_find_user_by_email(email):
    """Local SQLite fallback for finding user by email."""
    if not email:
        return None
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT google_id FROM chat_profiles WHERE email = ? LIMIT 1",
            (email.lower(),)
        )
        row = cursor.fetchone()
        if row:
            return row["google_id"]
        
        # Also check friends table
        cursor.execute(
            "SELECT friend_google_id FROM chat_friends WHERE friend_email = ? LIMIT 1",
            (email.lower(),)
        )
        row = cursor.fetchone()
        return row["friend_google_id"] if row else None
    except Exception as e:
        logging.info(f"Local DB find_user_by_email failed: {e}")
        return None


def lb_get_profile(google_id):
    """Local SQLite fallback for getting profile."""
    if not google_id:
        return None
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM chat_profiles WHERE google_id = ? LIMIT 1",
            (google_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    except Exception as e:
        logging.info(f"Local DB get_profile failed: {e}")
        return None


def lb_upsert_profile(google_id, email, display_name):
    """Local SQLite fallback for upserting profile."""
    if not google_id:
        return False, "No Google ID"
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO chat_profiles (google_id, email, display_name, updated_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(google_id) DO UPDATE SET 
                 email = excluded.email, 
                 display_name = excluded.display_name,
                 updated_at = CURRENT_TIMESTAMP""",
            (google_id, email, display_name)
        )
        conn.commit()
        
        cursor.execute(
            "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
            ("chat_profiles", google_id, "upsert")
        )
        conn.commit()
        return True, None
    except Exception as e:
        logging.info(f"Local DB upsert_profile failed: {e}")
        return False, "Database error"


def lb_set_public_key(google_id, public_key_b64):
    """Local SQLite fallback for setting public key."""
    if not google_id or not public_key_b64:
        return False
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE chat_profiles SET public_key = ?, updated_at = CURRENT_TIMESTAMP WHERE google_id = ?",
            (public_key_b64, google_id)
        )
        conn.commit()
        
        if cursor.rowcount > 0:
            cursor.execute(
                "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
                ("chat_profiles", google_id, "update")
            )
            conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB set_public_key failed: {e}")
        return False


def lb_get_public_key(google_id):
    """Local SQLite fallback for getting public key."""
    profile = lb_get_profile(google_id)
    return (profile or {}).get("public_key")


def lb_is_friend(owner_google_id, other_google_id):
    """Local SQLite fallback for checking friendship."""
    if not owner_google_id or not other_google_id:
        return False
    if str(owner_google_id) == str(other_google_id):
        return False
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM chat_friends WHERE owner_google_id = ? AND friend_google_id = ? LIMIT 1",
            (owner_google_id, other_google_id)
        )
        if cursor.fetchone():
            return True
        cursor.execute(
            "SELECT 1 FROM chat_friends WHERE owner_google_id = ? AND friend_google_id = ? LIMIT 1",
            (other_google_id, owner_google_id)
        )
        return cursor.fetchone() is not None
    except Exception as e:
        logging.info(f"Local DB is_friend failed: {e}")
        return False


def lb_save_direct_message(dm_room, sender_gid, sender_name, recipient_gid, mtype, ciphertext,
                            client_id=None, reply_to=None, mime=None, duration=None):
    """Local SQLite fallback for saving direct message."""
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO chat_direct_messages 
               (dm_room, sender_google_id, sender_name, recipient_google_id, type, ciphertext, 
                client_id, reply_to, mime, duration, created_at, synced)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 0)""",
            (dm_room, sender_gid, sender_name, recipient_gid, mtype, ciphertext,
             client_id, reply_to, mime, duration)
        )
        conn.commit()
        
        cursor.execute(
            "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
            ("chat_direct_messages", cursor.lastrowid, "insert")
        )
        conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB save_direct_message failed: {e}")
        return False


def lb_list_direct_messages(dm_room, limit=100):
    """Local SQLite fallback for listing direct messages."""
    if not dm_room:
        return []
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM chat_direct_messages WHERE dm_room = ? ORDER BY created_at ASC LIMIT ?",
            (dm_room, limit)
        )
        return [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        logging.info(f"Local DB list_direct_messages failed: {e}")
        return []


# ── Friend Requests - Local Fallback ──
def lb_create_friend_request(sender_gid, sender_email, recipient_email, recipient_gid=None):
    """Local SQLite fallback for creating friend request."""
    if not sender_gid:
        return False, "No sender Google ID"
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO chat_friend_requests 
               (sender_google_id, sender_email, recipient_google_id, recipient_email, status)
               VALUES (?, ?, ?, ?, 'pending')""",
            (sender_gid, sender_email, recipient_gid, recipient_email)
        )
        conn.commit()
        
        cursor.execute(
            "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
            ("chat_friend_requests", cursor.lastrowid, "insert")
        )
        conn.commit()
        return True, None
    except Exception as e:
        logging.info(f"Local DB create_friend_request failed: {e}")
        return False, "Database error"


def lb_list_incoming_requests(recipient_gid, status="pending"):
    """Local SQLite fallback for listing incoming friend requests."""
    if not recipient_gid:
        return []
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM chat_friend_requests WHERE recipient_google_id = ? AND status = ? ORDER BY created_at DESC",
            (recipient_gid, status)
        )
        return [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        logging.info(f"Local DB list_incoming_requests failed: {e}")
        return []


def lb_list_outgoing_requests(sender_gid, status="pending"):
    """Local SQLite fallback for listing outgoing friend requests."""
    if not sender_gid:
        return []
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM chat_friend_requests WHERE sender_google_id = ? AND status = ? ORDER BY created_at DESC",
            (sender_gid, status)
        )
        return [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        logging.info(f"Local DB list_outgoing_requests failed: {e}")
        return []


def lb_get_friend_request(request_id):
    """Local SQLite fallback for getting friend request."""
    if not request_id:
        return None
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM chat_friend_requests WHERE id = ? LIMIT 1",
            (int(request_id),)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    except Exception as e:
        logging.info(f"Local DB get_friend_request failed: {e}")
        return None


def lb_respond_friend_request(request_id, status):
    """Local SQLite fallback for responding to friend request."""
    if not request_id:
        return False
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE chat_friend_requests SET status = ?, responded_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, int(request_id))
        )
        conn.commit()
        
        if cursor.rowcount > 0:
            cursor.execute(
                "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
                ("chat_friend_requests", int(request_id), "update")
            )
            conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB respond_friend_request failed: {e}")
        return False


def lb_cancel_friend_request(request_id, sender_gid):
    """Local SQLite fallback for canceling friend request."""
    if not request_id:
        return False
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM chat_friend_requests WHERE id = ? AND sender_google_id = ? AND status = 'pending'",
            (int(request_id), sender_gid)
        )
        conn.commit()
        
        if cursor.rowcount > 0:
            cursor.execute(
                "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
                ("chat_friend_requests", int(request_id), "delete")
            )
            conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB cancel_friend_request failed: {e}")
        return False


# ── Notifications - Local Fallback ──
def lb_add_notification(owner_google_id, kind, title, body="", room_code=None):
    """Local SQLite fallback for adding notification."""
    if not owner_google_id:
        return False
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO chat_notifications 
               (owner_google_id, kind, title, body, room_code, read, created_at)
               VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)""",
            (owner_google_id, kind, title[:200], (body or "")[:500], room_code)
        )
        conn.commit()
        
        cursor.execute(
            "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
            ("chat_notifications", cursor.lastrowid, "insert")
        )
        conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB add_notification failed: {e}")
        return False


def lb_list_notifications(owner_google_id, limit=30):
    """Local SQLite fallback for listing notifications."""
    if not owner_google_id:
        return []
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM chat_notifications WHERE owner_google_id = ? ORDER BY created_at DESC LIMIT ?",
            (owner_google_id, limit)
        )
        return [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        logging.info(f"Local DB list_notifications failed: {e}")
        return []


def lb_mark_notifications_read(owner_google_id):
    """Local SQLite fallback for marking notifications as read."""
    if not owner_google_id:
        return False


def lb_list_announcements(active_only=True):
    """Local SQLite fallback for listing announcements."""
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        if active_only:
            cursor.execute(
                "SELECT * FROM chat_announcements WHERE is_active = 1 ORDER BY created_at DESC",
            )
        else:
            cursor.execute(
                "SELECT * FROM chat_announcements ORDER BY created_at DESC",
            )
        rows = [dict(r) for r in cursor.fetchall()]
        return rows
    except Exception as e:
        logging.info(f"Local DB list_announcements failed: {e}")
        return []


def lb_create_announcement(title, content):
    """Local SQLite fallback for creating announcement."""
    if not title or not content:
        return False, "Title and content required"
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO chat_announcements 
               (title, content, is_active, created_at, updated_at)
               VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
            (title, content)
        )
        conn.commit()
        
        # Mark for sync to Supabase
        cursor.execute(
            "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
            ("chat_announcements", cursor.lastrowid, "insert")
        )
        conn.commit()
        return True, None
    except Exception as e:
        logging.info(f"Local DB create_announcement failed: {e}")
        return False, str(e)


def lb_delete_announcement(announcement_id):
    """Local SQLite fallback for deleting announcement."""
    if not announcement_id:
        return False
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM chat_announcements WHERE id = ?",
            (announcement_id,)
        )
        conn.commit()
        
        # Mark for sync to Supabase
        cursor.execute(
            "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
            ("chat_announcements", announcement_id, "delete")
        )
        conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB delete_announcement failed: {e}")
        return False


def lb_toggle_announcement(announcement_id, is_active):
    """Local SQLite fallback for toggling announcement active status."""
    if not announcement_id:
        return False
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE chat_announcements SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (1 if is_active else 0, announcement_id)
        )
        conn.commit()
        
        # Mark for sync to Supabase
        cursor.execute(
            "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
            ("chat_announcements", announcement_id, "update")
        )
        conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB toggle_announcement failed: {e}")
        return False

    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE chat_notifications SET read = 1 WHERE owner_google_id = ? AND read = 0",
            (owner_google_id,)
        )
        conn.commit()
        
        if cursor.rowcount > 0:
            cursor.execute(
                "INSERT INTO pending_sync (table_name, record_id, action) VALUES (?, ?, ?)",
                ("chat_notifications", owner_google_id, "update")
            )
            conn.commit()
        return True
    except Exception as e:
        logging.info(f"Local DB mark_notifications_read failed: {e}")
        return False


def lb_unread_notification_count(owner_google_id):
    """Local SQLite fallback for counting unread notifications."""
    if not owner_google_id:
        return 0
    try:
        conn = _get_local_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM chat_notifications WHERE owner_google_id = ? AND read = 0",
            (owner_google_id,)
        )
        row = cursor.fetchone()
        return row["cnt"] if row else 0
    except Exception as e:
        logging.info(f"Local DB unread_notification_count failed: {e}")
        return 0


# ── Sync Functions ──
def sync_pending_to_supabase():
    """Sync all pending local changes to Supabase when it comes back online."""
    if not supabase_available():
        return False
    
    conn = _get_local_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM pending_sync ORDER BY created_at ASC LIMIT 50")
    pending = cursor.fetchall()
    
    if not pending:
        return True
    
    synced_count = 0
    errors = []
    
    for p in pending:
        try:
            table = p["table_name"]
            record_id = p["record_id"]
            action = p["action"]
            
            if table == "chat_profiles" and action in ["insert", "upsert", "update"]:
                cursor.execute("SELECT * FROM chat_profiles WHERE google_id = ?", (record_id,))
                row = cursor.fetchone()
                if row:
                    profile = dict(row)
                    r = _requests.post(
                        f"{SUPABASE_URL}/rest/v1/chat_profiles",
                        headers={**_supabase_headers(), "Prefer": "resolution=merge-duplicates"},
                        json={
                            "google_id": profile["google_id"],
                            "email": profile["email"],
                            "display_name": profile["display_name"],
                            "public_key": profile.get("public_key"),
                            "updated_at": profile["updated_at"],
                        },
                        timeout=8,
                    )
                    if r.status_code < 400:
                        cursor.execute("DELETE FROM pending_sync WHERE id = ?", (p["id"],))
                        conn.commit()
                        synced_count += 1
                    else:
                        errors.append(f"chat_profiles {record_id}: HTTP {r.status_code}")
            
            elif table == "chat_friends" and action == "insert":
                cursor.execute("SELECT * FROM chat_friends WHERE id = ?", (record_id,))
                row = cursor.fetchone()
                if row:
                    friend = dict(row)
                    r = _requests.post(
                        f"{SUPABASE_URL}/rest/v1/chat_friends",
                        headers={**_supabase_headers(), "Prefer": "resolution=merge-duplicates"},
                        json={
                            "owner_google_id": friend["owner_google_id"],
                            "owner_email": friend.get("owner_email"),
                            "friend_google_id": friend.get("friend_google_id"),
                            "friend_email": friend.get("friend_email"),
                            "friend_display_name": friend.get("friend_display_name"),
                        },
                        timeout=8,
                    )
                    if r.status_code < 400:
                        cursor.execute("DELETE FROM pending_sync WHERE id = ?", (p["id"],))
                        conn.commit()
                        synced_count += 1
                    else:
                        errors.append(f"chat_friends {record_id}: HTTP {r.status_code}")
            
            elif table == "chat_friends" and action == "delete":
                r = _requests.delete(
                    f"{SUPABASE_URL}/rest/v1/chat_friends",
                    headers=_supabase_headers(),
                    params={
                        "owner_google_id": f"eq.{record_id}",
                        "friend_google_id": f"eq.{record_id}"
                    },
                    timeout=8,
                )
                if r.status_code < 400:
                    cursor.execute("DELETE FROM pending_sync WHERE id = ?", (p["id"],))
                    conn.commit()
                    synced_count += 1
                else:
                    errors.append(f"chat_friends delete {record_id}: HTTP {r.status_code}")
            
            elif table == "chat_direct_messages" and action == "insert":
                cursor.execute("SELECT * FROM chat_direct_messages WHERE id = ?", (record_id,))
                row = cursor.fetchone()
                if row:
                    msg = dict(row)
                    r = _requests.post(
                        f"{SUPABASE_URL}/rest/v1/chat_direct_messages",
                        headers=_supabase_headers(),
                        json={
                            "dm_room": msg["dm_room"],
                            "sender_google_id": msg["sender_google_id"],
                            "sender_name": msg["sender_name"],
                            "recipient_google_id": msg["recipient_google_id"],
                            "type": msg["type"],
                            "ciphertext": msg["ciphertext"],
                            "client_id": msg.get("client_id"),
                            "reply_to": msg.get("reply_to"),
                            "mime": msg.get("mime"),
                            "duration": msg.get("duration"),
                        },
                        timeout=8,
                    )
                    if r.status_code < 400:
                        cursor.execute(
                            "UPDATE chat_direct_messages SET synced = 1 WHERE id = ?",
                            (record_id,)
                        )
                        cursor.execute("DELETE FROM pending_sync WHERE id = ?", (p["id"],))
                        conn.commit()
                        synced_count += 1
                    else:
                        errors.append(f"chat_direct_messages {record_id}: HTTP {r.status_code}")
            
            elif table == "chat_friend_requests" and action == "insert":
                cursor.execute("SELECT * FROM chat_friend_requests WHERE id = ?", (record_id,))
                row = cursor.fetchone()
                if row:
                    req = dict(row)
                    r = _requests.post(
                        f"{SUPABASE_URL}/rest/v1/chat_friend_requests",
                        headers=_supabase_headers(),
                        json={
                            "sender_google_id": req["sender_google_id"],
                            "sender_email": req.get("sender_email"),
                            "recipient_google_id": req.get("recipient_google_id"),
                            "recipient_email": req.get("recipient_email"),
                            "status": req["status"],
                        },
                        timeout=8,
                    )
                    if r.status_code < 400:
                        cursor.execute("DELETE FROM pending_sync WHERE id = ?", (p["id"],))
                        conn.commit()
                        synced_count += 1
                    else:
                        errors.append(f"chat_friend_requests {record_id}: HTTP {r.status_code}")
            
            elif table == "chat_notifications" and action == "insert":
                cursor.execute("SELECT * FROM chat_notifications WHERE id = ?", (record_id,))
                row = cursor.fetchone()
                if row:
                    notif = dict(row)
                    r = _requests.post(
                        f"{SUPABASE_URL}/rest/v1/chat_notifications",
                        headers=_supabase_headers(),
                        json={
                            "owner_google_id": notif["owner_google_id"],
                            "kind": notif["kind"],
                            "title": notif["title"],
                            "body": notif.get("body", ""),
                            "room_code": notif.get("room_code"),
                            "read": bool(notif.get("read", 0)),
                        },
                        timeout=8,
                    )
                    if r.status_code < 400:
                        cursor.execute("DELETE FROM pending_sync WHERE id = ?", (p["id"],))
                        conn.commit()
                        synced_count += 1
                    else:
                        errors.append(f"chat_notifications {record_id}: HTTP {r.status_code}")
            
            # Update attempts
            cursor.execute(
                "UPDATE pending_sync SET attempts = attempts + 1 WHERE id = ?",
                (p["id"],)
            )
            conn.commit()
            
        except Exception as e:
            errors.append(f"{table} {record_id}: sync error")
    
    logging.info(f"Synced {synced_count} pending items to Supabase. Errors: {len(errors)}")
    if errors:
        logging.info(f"Sync errors: {errors}")
    
    return synced_count > 0


def start_sync_worker():
    """Background thread to periodically sync pending changes to Supabase."""
    def sync_loop():
        while True:
            time.sleep(30)  # Check every 30 seconds
            if supabase_available() and not DB_STATUS["ok"]:
                # Supabase was down, now try to sync
                if check_db_status():
                    sync_pending_to_supabase()
    
    t = threading.Thread(target=sync_loop, daemon=True)
    t.start()


# ── Helper functions for DMs ──
def resolve_google_id(identifier):
    if not identifier:
        return None
    s = str(identifier).strip()
    if "@" in s:
        found = sb_find_user_by_email(s.lower())
        if found:
            return str(found).strip()
    return s

def get_dm_room_id(gid_a, gid_b):
    if not gid_a or not gid_b:
        return None
    a = resolve_google_id(gid_a)
    b = resolve_google_id(gid_b)
    if not a or not b:
        return None
    sorted_ids = sorted([a, b])
    return "dm_" + hashlib.sha256((sorted_ids[0] + ":" + sorted_ids[1]).encode()).hexdigest()[:16]


# ── Admin Statistics ──
connected_users = {}  # {google_id: {name, email, connected_at, last_active}}
active_dm_rooms = {}  # {dm_room: {user1_gid, user2_gid, created_at, message_count}}

def require_google():
    if not session.get("google_id"):
        abort(401)

def get_admin_stats():
    with _state_lock:
        total_users = len(connected_users)
        total_active_dms = len(active_dm_rooms)
        total_messages = sum(r.get("message_count", 0) for r in active_dm_rooms.values())
    return {
        "total_users": total_users,
        "total_active_dms": total_active_dms,
        "total_messages": total_messages,
    }


# =============================================================================
# ROUTES
# =============================================================================

@app.before_request
def _verify_google_session_once():
    if session.get("google_id") and not session.get("_google_verified"):
        if supabase_available():
            profile = sb_get_profile(session["google_id"])
            if profile and profile.get("display_name"):
                session["preferred_name"] = profile["display_name"]
        session["_google_verified"] = True


@app.before_request
def _check_db_and_alert():
    """Check database status and add alert to all responses if down."""
    db_status = get_db_status()
    if not db_status["ok"] and db_status["configured"]:
        # Database is configured but not responding
        # Add a flash message for any page that might need DB
        if request.endpoint and request.endpoint not in ['static', 'vapid_public_key']:
            if not session.get("_db_alert_shown"):
                flash(
                    f"⚠️ Database connection issue: {db_status['error'] or 'Service unavailable'}. "
                    "Some features may be limited.",
                    "warning"
                )
                session["_db_alert_shown"] = True
            elif session.get("_db_alert_shown") and request.endpoint in ['index', 'account']:
                # Re-check and clear if back online
                if DB_STATUS["ok"]:
                    session.pop("_db_alert_shown", None)


@app.route("/")
def index():
    gid = session.get("google_id")
    friends, notifications, pending_requests, outgoing_requests = [], [], [], []
    db_ok = True
    db_error = None
    
    if gid:
        db_ok = check_db_status()
        if db_ok:
            friends = sb_list_friends(gid)
            notifications = sb_list_notifications(gid, limit=20)
            pending_requests = sb_list_incoming_requests(gid)
            outgoing_requests = sb_list_outgoing_requests(gid)
        else:
            db_error = DB_STATUS["last_error"]
    
    return render_template(
        "index.html",
        username=session.get("preferred_name") or session.get("name", "Guest"),
        google_signed_in=bool(gid),
        google_id=gid or "",
        google_email=session.get("google_email", ""),
        home_friends=friends,
        home_notifications=notifications,
        pending_requests=pending_requests,
        outgoing_requests=outgoing_requests,
        db_ok=db_ok,
        db_error=db_error,
        db_configured=supabase_available(),
    )


@app.route("/auth/google/login")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return google_oauth.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    try:
        token = google_oauth.authorize_access_token()
        userinfo = token.get("userinfo")
    except Exception as e:
        logging.info(f"Google auth failed: {e}")
        flash("Google sign-in failed.", "error")
        return redirect(url_for("index"))
    if not userinfo or not userinfo.get("sub"):
        flash("Google sign-in failed.", "error")
        return redirect(url_for("index"))
    session.permanent = True
    session["google_id"] = userinfo["sub"]
    session["google_email"] = userinfo.get("email", "")

    profile = sb_get_profile(userinfo["sub"])
    if profile and profile.get("display_name"):
        session["preferred_name"] = profile["display_name"]
    elif userinfo.get("name"):
        seed_name = re.sub(r"[^A-Za-z0-9_\- ]", "", userinfo["name"])[:24].strip()
        if seed_name:
            session["preferred_name"] = seed_name
            sb_upsert_profile(userinfo["sub"], userinfo.get("email", ""), seed_name)

    flash("Signed in with Google. Start chatting with your friends!", "info")
    return redirect(url_for("index"))


@app.route("/auth/google/logout")
def google_logout():
    gid = session.pop("google_id", None)
    session.pop("google_email", None)
    session.pop("preferred_name", None)
    session.pop("_google_verified", None)
    if gid:
        with _state_lock:
            push_subscriptions.pop(gid, None)
            connected_users.pop(gid, None)
    flash("Signed out of Google.", "info")
    return redirect(url_for("index"))


@app.route("/vapid-public-key")
def vapid_public_key():
    return jsonify({"key": VAPID_PUBLIC_KEY})


@app.route("/save-subscription", methods=["POST"])
@rate_limited("save_subscription")
def save_subscription():
    check_csrf()
    gid = session.get("google_id")
    if not gid:
        return jsonify({"ok": False, "reason": "google_signin_required"}), 401
    sub = request.get_json(silent=True)
    if not sub or "endpoint" not in sub:
        return jsonify({"ok": False}), 400
    with _state_lock:
        push_subscriptions[gid] = sub
    return jsonify({"ok": True})


@app.route("/remove-subscription", methods=["POST"])
@rate_limited("remove_subscription")
def remove_subscription():
    check_csrf()
    gid = session.get("google_id")
    if gid:
        with _state_lock:
            push_subscriptions.pop(gid, None)
    return jsonify({"ok": True})


# -- Account Dashboard --
@app.route("/account")
def account():
    if not session.get("google_id"):
        return redirect(url_for("index"))
    gid = session["google_id"]
    friends = sb_list_friends(gid)
    profile = sb_get_profile(gid)
    preferred_name = (profile or {}).get("display_name") or session.get("preferred_name", "")
    return render_template(
        "account.html",
        username=session.get("name", "Guest"),
        google_email=session.get("google_email", ""),
        google_id=gid,
        has_subscription=gid in push_subscriptions,
        friends=friends,
        supabase_available=supabase_available(),
        preferred_name=preferred_name,
    )


@app.route("/account/update-name", methods=["POST"])
@rate_limited("update_name")
def update_name():
    check_csrf()
    require_google()
    gid = session["google_id"]
    new_name = (request.form.get("display_name") or "").strip()
    NAME_RE = re.compile(r"^[A-Za-z0-9_\- ]{1,24}$")
    if not NAME_RE.match(new_name):
        flash("Name must be 1-24 characters, letters/numbers/_/- only.", "error")
        return redirect(url_for("account"))
    if new_name.lower() in BAD_USERNAMES:
        flash("That name isn't allowed.", "error")
        return redirect(url_for("account"))
    ok, err = sb_upsert_profile(gid, session.get("google_email", ""), new_name)
    if ok:
        session["preferred_name"] = new_name
        flash("Display name updated.", "info")
    else:
        flash(f"Couldn't update name: {err or 'unknown error'}", "error")
    return redirect(url_for("account"))


@app.route("/account/friends/add", methods=["POST"])
@rate_limited("add_friend")
def add_friend():
    check_csrf()
    require_google()
    gid = session["google_id"]
    email = (request.form.get("friend_email") or "").strip().lower()
    if not email or "@" not in email:
        flash("Enter a valid email address.", "error")
        return redirect(url_for("account"))
    if email == (session.get("google_email") or "").lower():
        flash("You can't add yourself.", "error")
        return redirect(url_for("account"))

    friend_gid = sb_find_user_by_email(email)
    my_email = session.get("google_email", "")
    ok, err = sb_create_friend_request(
        sender_gid=gid,
        sender_email=my_email,
        recipient_email=email,
        recipient_gid=friend_gid,
    )
    if ok:
        if friend_gid:
            flash(f"Friend request sent to {email}.", "info")
            sb_add_notification(
                friend_gid, "friend_request",
                "New friend request",
                f"{my_email or 'Someone'} wants to be your friend.",
            )
            send_push(friend_gid, "New friend request", f"{my_email or 'Someone'} wants to be your friend.")
        else:
            flash(f"Request sent to {email}. They'll see it once they sign in with Google.", "info")
    else:
        flash(err or "Couldn't send friend request.", "error")
    return redirect(url_for("account"))


@app.route("/account/friends/remove", methods=["POST"])
@rate_limited("remove_friend")
def remove_friend():
    check_csrf()
    require_google()
    gid = session["google_id"]
    friend_gid = request.form.get("friend_google_id", "")
    if friend_gid and sb_remove_friend(gid, friend_gid):
        flash("Friend removed.", "info")
    else:
        flash("Couldn't remove friend.", "error")
    return redirect(url_for("account"))


# -- Friend Request API --
@app.route("/api/friend-requests")
def api_friend_requests():
    gid = session.get("google_id")
    if not gid:
        return jsonify({"requests": []})
    reqs = sb_list_incoming_requests(gid)
    return jsonify({"requests": reqs})


@app.route("/api/friend-requests/<request_id>/accept", methods=["POST"])
@rate_limited("api_accept_friend_request")
def api_accept_friend_request(request_id):
    check_csrf()
    require_google()
    gid = session["google_id"]
    req = sb_get_friend_request(request_id)
    if not req or req.get("recipient_google_id") != gid or req.get("status") != "pending":
        return jsonify({"ok": False, "error": "Request not found."}), 404

    sb_respond_friend_request(request_id, "accepted")

    my_email = session.get("google_email", "")
    sb_add_friend(gid, my_email, req["sender_google_id"], req.get("sender_email", ""), None)
    sb_add_friend(req["sender_google_id"], req.get("sender_email", ""), gid, my_email, None)

    sb_add_notification(
        req["sender_google_id"], "friend_added",
        "Friend request accepted",
        f"{my_email or 'Someone'} accepted your friend request.",
    )
    send_push(req["sender_google_id"], "Friend request accepted", f"{my_email or 'Someone'} accepted your friend request.")
    return jsonify({"ok": True})


@app.route("/api/friend-requests/<request_id>/decline", methods=["POST"])
@rate_limited("api_decline_friend_request")
def api_decline_friend_request(request_id):
    check_csrf()
    require_google()
    gid = session["google_id"]
    req = sb_get_friend_request(request_id)
    if not req or req.get("recipient_google_id") != gid or req.get("status") != "pending":
        return jsonify({"ok": False, "error": "Request not found."}), 404
    sb_respond_friend_request(request_id, "declined")
    return jsonify({"ok": True})


@app.route("/api/friend-requests/<request_id>/cancel", methods=["POST"])
@rate_limited("api_cancel_friend_request")
def api_cancel_friend_request(request_id):
    check_csrf()
    require_google()
    gid = session["google_id"]
    ok = sb_cancel_friend_request(request_id, gid)
    if not ok:
        return jsonify({"ok": False, "error": "Couldn't cancel request."}), 404
    return jsonify({"ok": True})


@app.route("/api/friends/add", methods=["POST"])
@rate_limited("api_add_friend")
def api_add_friend():
    check_csrf()
    if not session.get("google_id"):
        return jsonify({"ok": False, "error": "Please sign in with Google first."}), 401
    gid = session["google_id"]
    data = request.get_json(silent=True) or request.form
    email = (data.get("friend_email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Enter a valid Google email address."}), 400
    if email == (session.get("google_email") or "").lower():
        return jsonify({"ok": False, "error": "You cannot add yourself."}), 400

    friend_gid = sb_find_user_by_email(email)
    my_email = session.get("google_email", "")
    ok, err = sb_create_friend_request(
        sender_gid=gid,
        sender_email=my_email,
        recipient_email=email,
        recipient_gid=friend_gid,
    )
    if ok:
        if friend_gid:
            sb_add_notification(
                friend_gid, "friend_request",
                "New friend request",
                f"{my_email or 'Someone'} wants to be your friend.",
            )
            send_push(friend_gid, "New friend request", f"{my_email or 'Someone'} wants to be your friend.")
            return jsonify({"ok": True, "message": f"Friend request sent to {email}."})
        else:
            return jsonify({"ok": True, "message": f"Request sent to {email}. They'll see it once they sign in with Google."})
    return jsonify({"ok": False, "error": err or "Couldn't send friend request."}), 400


@app.route("/api/dm/<friend_gid>/messages")
def api_get_dm_messages(friend_gid):
    my_gid = session.get("google_id")
    if not my_gid:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    resolved_friend = resolve_google_id(friend_gid) or friend_gid
    if not sb_is_friend(my_gid, resolved_friend):
        return jsonify({"ok": False, "error": "Not friends with this user."}), 403
    dm_room = get_dm_room_id(my_gid, resolved_friend)
    if not dm_room:
        return jsonify({"ok": False, "error": "Invalid DM room"}), 400
    msgs = sb_list_direct_messages(dm_room, limit=100)
    return jsonify({"ok": True, "messages": msgs, "dm_room": dm_room})


@app.route("/api/pubkey/set", methods=["POST"])
@rate_limited("api_set_pubkey")
def api_set_pubkey():
    check_csrf()
    require_google()
    gid = session["google_id"]
    data = request.get_json(silent=True) or {}
    pubkey = (data.get("public_key") or "").strip()
    if not pubkey or len(pubkey) > 500:
        return jsonify({"ok": False, "error": "Invalid public key."}), 400
    ok = sb_set_public_key(gid, pubkey)
    return jsonify({"ok": ok})


@app.route("/api/pubkey/<gid>")
def api_get_pubkey(gid):
    my_gid = session.get("google_id")
    if not my_gid:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    resolved = resolve_google_id(gid) or gid
    if str(resolved) != str(my_gid) and not sb_is_friend(my_gid, resolved):
        return jsonify({"ok": False, "error": "Not friends with this user."}), 403
    pubkey = sb_get_public_key(resolved)
    if not pubkey:
        return jsonify({"ok": False, "error": "No public key on file yet."}), 404
    return jsonify({"ok": True, "public_key": pubkey, "google_id": resolved})


@app.route("/api/notifications/mark-read", methods=["POST"])
@rate_limited("api_mark_notifications_read")
def api_mark_notifications_read():
    check_csrf()
    require_google()
    ok = sb_mark_notifications_read(session["google_id"])
    return jsonify({"ok": ok})


@app.route("/api/notifications/unread-count")
def api_unread_count():
    gid = session.get("google_id")
    if not gid:
        return jsonify({"count": 0})
    return jsonify({"count": sb_unread_notification_count(gid)})


@app.route("/account/test-push", methods=["POST"])
@rate_limited("test_push")
def test_push():
    check_csrf()
    require_google()
    gid = session["google_id"]
    if gid not in push_subscriptions:
        flash("No push subscription found.", "error")
        return redirect(url_for("account"))
    send_push(gid, "Private.Chat", "This is a test notification. Push is working.")
    flash("Test notification sent.", "info")
    return redirect(url_for("account"))


# =============================================================================
# ADMIN ROUTES
# =============================================================================

@app.route("/admin/login", methods=["GET", "POST"])
@rate_limited("admin_login")
def admin_login():
    if request.method == "POST":
        key = "admin:" + client_ip()
        if check_lockout(key):
            flash("Too many attempts. Try again later.", "error")
            return render_template("admin_login.html", totp_required=bool(TOTP_SECRET))
        pw = request.form.get("password", "")
        code = request.form.get("totp", "")
        pw_ok = check_password_hash(ADMIN_PASSWORD_HASH, pw)
        totp_ok = (not TOTP_SECRET) or verify_totp(TOTP_SECRET, code)
        if pw_ok and totp_ok:
            record_success(key)
            session.permanent = True
            session["is_admin"] = True
            flash("Logged in.", "info")
            return redirect(url_for("admin_dashboard"))
        record_failure(key)
        logging.warning(f"Failed admin login from {client_ip()}")
        flash("Incorrect password or code.", "error")
    return render_template("admin_login.html", totp_required=bool(TOTP_SECRET))


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("index"))


@app.route("/admin")
def admin_dashboard():
    require_admin()
    stats = get_admin_stats()
    db_ok = check_db_status()
    db_error = DB_STATUS["last_error"] if not db_ok else None
    
    # Get all users with active sessions
    all_users = []
    if db_ok:
        with _state_lock:
            for gid, user_data in connected_users.items():
                profile = sb_get_profile(gid)
                all_users.append({
                    "google_id": gid,
                    "name": user_data.get("name", "Unknown"),
                    "email": user_data.get("email", ""),
                    "connected_at": user_data.get("connected_at", ""),
                    "last_active": user_data.get("last_active", ""),
                    "display_name": profile.get("display_name", "") if profile else "",
                })
    else:
        # Fallback: show connected users from memory
        with _state_lock:
            for gid, user_data in connected_users.items():
                all_users.append({
                    "google_id": gid,
                    "name": user_data.get("name", "Unknown"),
                    "email": user_data.get("email", ""),
                    "connected_at": user_data.get("connected_at", ""),
                    "last_active": user_data.get("last_active", ""),
                    "display_name": "",
                })
    
    # Get active DM rooms
    active_dms = []
    if db_ok:
        with _state_lock:
            for dm_room, room_data in active_dm_rooms.items():
                user1 = sb_get_profile(room_data.get("user1_gid"))
                user2 = sb_get_profile(room_data.get("user2_gid"))
                active_dms.append({
                    "dm_room": dm_room,
                    "user1": user1.get("display_name", "Unknown") if user1 else "Unknown",
                    "user1_email": user1.get("email", "") if user1 else "",
                    "user2": user2.get("display_name", "Unknown") if user2 else "Unknown",
                    "user2_email": user2.get("email", "") if user2 else "",
                    "created_at": room_data.get("created_at", ""),
                    "message_count": room_data.get("message_count", 0),
                })
    else:
        # Fallback: show DM rooms from memory
        with _state_lock:
            for dm_room, room_data in active_dm_rooms.items():
                active_dms.append({
                    "dm_room": dm_room,
                    "user1": "User",
                    "user1_email": "",
                    "user2": "User",
                    "user2_email": "",
                    "created_at": room_data.get("created_at", ""),
                    "message_count": room_data.get("message_count", 0),
                })
    
    return render_template(
        "admin.html",
        stats=stats,
        users=all_users,
        active_dms=active_dms,
        db_ok=db_ok,
        db_error=db_error,
        db_configured=supabase_available(),
    )


@app.route("/admin/broadcast", methods=["POST"])
@rate_limited("admin_broadcast")
def admin_broadcast():
    require_admin()
    check_csrf()
    title = (request.form.get("title") or "Announcement").strip()[:80]
    body = (request.form.get("body") or "").strip()
    if not body:
        flash("Message can't be empty.", "error")
        return redirect(url_for("admin_dashboard"))
    if len(body) > 500:
        flash("Message is too long.", "error")
        return redirect(url_for("admin_dashboard"))
    
    with _state_lock:
        targets = list(push_subscriptions.keys())
    
    sent = 0
    for gid in targets:
        send_push(gid, title, body, {"type": "admin_broadcast"})
        sent += 1
    
    flash(f"Broadcast sent to {sent} subscribed device(s).", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/push-broadcast", methods=["POST"])
@rate_limited("admin_push_broadcast")
def admin_push_broadcast():
    require_admin()
    check_csrf()
    title = (request.form.get("push_title") or "Private.Chat").strip()[:80]
    body = (request.form.get("push_body") or "").strip()
    if not body:
        flash("Push message can't be empty.", "error")
        return redirect(url_for("admin_dashboard"))
    if len(body) > 500:
        flash("Push message is too long.", "error")
        return redirect(url_for("admin_dashboard"))
    with _state_lock:
        targets = list(push_subscriptions.keys())
    sent = 0
    for gid in targets:
        send_push(gid, title, body)
        sent += 1
    flash(f"Push sent to {sent} subscribed device(s).", "info")
    return redirect(url_for("admin_dashboard"))


#  Admin Announcements 
@app.route("/admin/announcements")
def admin_announcements():
    require_admin()
    announcements = sb_list_announcements(active_only=False)
    return render_template("admin_announcements.html", announcements=announcements)


@app.route("/admin/announcements/create", methods=["POST"])
@rate_limited("admin_create_announcement")
def admin_create_announcement():
    require_admin()
    check_csrf()
    title = (request.form.get("title") or "").strip()
    content = (request.form.get("content") or "").strip()
    
    if not title or not content:
        flash("Title and content are required.", "error")
        return redirect(url_for("admin_announcements"))
    
    ok, err = sb_create_announcement(title, content)
    if ok:
        flash("Announcement created!", "info")
    else:
        flash(f"Failed to create announcement: {err}", "error")
    return redirect(url_for("admin_announcements"))


@app.route("/admin/announcements/<int:announcement_id>/delete", methods=["POST"])
@rate_limited("admin_delete_announcement")
def admin_delete_announcement(announcement_id):
    require_admin()
    check_csrf()
    ok = sb_delete_announcement(announcement_id)
    if ok:
        flash("Announcement deleted.", "info")
    else:
        flash("Failed to delete announcement.", "error")
    return redirect(url_for("admin_announcements"))


@app.route("/admin/announcements/<int:announcement_id>/toggle", methods=["POST"])
@rate_limited("admin_toggle_announcement")
def admin_toggle_announcement(announcement_id):
    require_admin()
    check_csrf()
    # Find current status
    announcements = sb_list_announcements(active_only=False)
    current = next((a for a in announcements if a["id"] == announcement_id), None)
    new_status = not current.get("is_active", False) if current else True
    
    ok = sb_toggle_announcement(announcement_id, new_status)
    if ok:
        flash(f"Announcement {'activated' if new_status else 'deactivated'}.", "info")
    else:
        flash("Failed to toggle announcement.", "error")
    return redirect(url_for("admin_announcements"))


# =============================================================================
# API: Database Status
# =============================================================================

@app.route("/api/db/status")
def api_db_status():
    """Public endpoint to check database status from client-side JavaScript."""
    status = get_db_status()
    return jsonify(status)


# =============================================================================
# SOCKET.IO EVENTS - Direct Messages Only
# =============================================================================

@socketio.on("connect")
def connect(auth=None):
    # WebSocket authentication check
    gid = session.get("google_id")
    if not gid:
        return False  # Reject connection if not authenticated
    
    join_room(f"user_{gid}")
    with _state_lock:
        connected_users[gid] = {
            "name": session.get("preferred_name") or session.get("name", "User"),
            "email": session.get("google_email", ""),
            "connected_at": datetime.datetime.utcnow().isoformat(),
            "last_active": datetime.datetime.utcnow().isoformat(),
        }
    if session.get("is_admin"):
        join_room("admin_channel")


@socketio.on("disconnect")
def disconnect():
    gid = session.get("google_id")
    if gid:
        with _state_lock:
            connected_users.pop(gid, None)


@socketio.on("join_dm")
def handle_join_dm(data):
    my_gid = session.get("google_id")
    if not my_gid:
        return
    raw_friend_gid = data.get("friend_gid")
    if not raw_friend_gid:
        return
    resolved_friend = resolve_google_id(raw_friend_gid) or raw_friend_gid
    if not sb_is_friend(my_gid, resolved_friend):
        emit("dm_error", {"error": "You can only message confirmed friends."})
        return
    dm_room = get_dm_room_id(my_gid, resolved_friend)
    if not dm_room:
        return
    join_room(dm_room)
    
    # Track active DM room
    with _state_lock:
        if dm_room not in active_dm_rooms:
            active_dm_rooms[dm_room] = {
                "user1_gid": min(my_gid, resolved_friend),
                "user2_gid": max(my_gid, resolved_friend),
                "created_at": datetime.datetime.utcnow().isoformat(),
                "message_count": 0,
            }
    
    emit("dm_joined", {"dm_room": dm_room, "friend_gid": resolved_friend})


@socketio.on("send_dm_message")
def handle_send_dm_message(data):
    my_gid = session.get("google_id")
    my_name = session.get("preferred_name") or email_to_name(session.get("google_email")) or session.get("name", "User")
    if not my_gid:
        return
    raw_friend = data.get("friend_gid")
    ciphertext = data.get("ciphertext")
    mtype = data.get("type", "text")
    mid = data.get("id") or str(uuid.uuid4())
    if not raw_friend or not ciphertext:
        return

    resolved_friend = resolve_google_id(raw_friend) or raw_friend
    if not sb_is_friend(my_gid, resolved_friend):
        emit("dm_error", {"error": "You can only message confirmed friends."})
        return
    dm_room = get_dm_room_id(my_gid, resolved_friend)
    if not dm_room:
        return

    reply_to = data.get("reply_to")
    duration = data.get("duration")
    mime = data.get("mime")

    ts = time.strftime('%H:%M %p')
    content = {
        "id": mid,
        "sender_gid": str(my_gid),
        "sender_name": my_name,
        "recipient_gid": str(resolved_friend),
        "dm_room": dm_room,
        "type": mtype,
        "ciphertext": ciphertext,
        "reply_to": reply_to,
        "duration": duration,
        "mime": mime,
        "timestamp": ts,
    }

    # Emit to the shared DM room AND the recipient's personal room
    socketio.emit("dm_message", content, to=dm_room)
    socketio.emit("dm_message", content, to=f"user_{resolved_friend}", include_self=False)

    # Update stats
    with _state_lock:
        if dm_room in active_dm_rooms:
            active_dm_rooms[dm_room]["message_count"] = active_dm_rooms[dm_room].get("message_count", 0) + 1
        else:
            active_dm_rooms[dm_room] = {
                "user1_gid": min(my_gid, resolved_friend),
                "user2_gid": max(my_gid, resolved_friend),
                "created_at": datetime.datetime.utcnow().isoformat(),
                "message_count": 1,
            }

    # Persist and notify in background
    def _bg_persist_and_notify():
        try:
            sb_save_direct_message(
                dm_room=dm_room,
                sender_gid=str(my_gid),
                sender_name=my_name,
                recipient_gid=str(resolved_friend),
                mtype=mtype,
                ciphertext=ciphertext,
                client_id=mid,
                reply_to=reply_to,
                mime=mime,
                duration=duration,
            )
            send_push(resolved_friend, f"Message from {my_name}", "You received an encrypted message", {"type": "dm", "dm_room": dm_room})
            sb_add_notification(resolved_friend, "message", f"Message from {my_name}", "You received an encrypted message")
        except Exception as ex:
            logging.info(f"Background DM persist error: {ex}")

    socketio.start_background_task(_bg_persist_and_notify)


@socketio.on("dm_typing")
def handle_dm_typing(data):
    my_gid = session.get("google_id")
    my_name = session.get("preferred_name") or email_to_name(session.get("google_email")) or "Friend"
    friend_gid = data.get("friend_gid")
    if not my_gid or not friend_gid:
        return
    resolved_friend = resolve_google_id(friend_gid) or friend_gid
    dm_room = get_dm_room_id(my_gid, resolved_friend)
    if not dm_room:
        return
    payload = {
        "sender_gid": str(my_gid),
        "sender_name": my_name,
        "active": bool(data.get("active"))
    }
    socketio.emit("dm_typing", payload, to=dm_room, include_self=False)
    socketio.emit("dm_typing", payload, to=f"user_{resolved_friend}", include_self=False)


@socketio.on("latency_ping")
def latency_ping(data):
    emit("latency_pong", {"t": data.get("t")})


@socketio.on("update_activity")
def update_activity():
    gid = session.get("google_id")
    if gid:
        with _state_lock:
            if gid in connected_users:
                connected_users[gid]["last_active"] = datetime.datetime.utcnow().isoformat()


# =============================================================================
# GIF API (Kept for fun)
# =============================================================================

@app.route("/api/gifs/search")
def api_search_gifs():
    query = request.args.get("q", "").strip()
    api_key = os.environ.get("GIPHY_API_KEY") or os.environ.get("GIPHY_KEY") or os.environ.get("GIFHY_API_KEY")

    fallback_gifs = [
        {"id": "artj92V8o75VPL7AeQ", "title": "Celebrate", "url": "https://media.giphy.com/media/artj92V8o75VPL7AeQ/giphy.gif", "preview": "https://media.giphy.com/media/artj92V8o75VPL7AeQ/giphy.gif"},
        {"id": "111ebonMs90YLu", "title": "Thumbs Up", "url": "https://media.giphy.com/media/111ebonMs90YLu/giphy.gif", "preview": "https://media.giphy.com/media/111ebonMs90YLu/giphy.gif"},
        {"id": "blSTtZehjAZ8I", "title": "Dance", "url": "https://media.giphy.com/media/blSTtZehjAZ8I/giphy.gif", "preview": "https://media.giphy.com/media/blSTtZehjAZ8I/giphy.gif"},
        {"id": "B0vFTrb0ZGDf2", "title": "Laugh", "url": "https://media.giphy.com/media/B0vFTrb0ZGDf2/giphy.gif", "preview": "https://media.giphy.com/media/B0vFTrb0ZGDf2/giphy.gif"},
    ]
    if query:
        q_lower = query.lower()
        filtered = [g for g in fallback_gifs if q_lower in g["title"].lower()]
        return jsonify({"ok": True, "gifs": filtered if filtered else fallback_gifs, "source": "fallback"})
    return jsonify({"ok": True, "gifs": fallback_gifs, "source": "fallback"})

    try:
        if query:
            url = "https://api.giphy.com/v1/gifs/search"
            params = {"api_key": api_key, "q": query, "limit": 24, "rating": "g"}
        else:
            url = "https://api.giphy.com/v1/gifs/trending"
            params = {"api_key": api_key, "limit": 24, "rating": "g"}

        resp = _requests.get(url, params=params, timeout=6)
        if resp.ok:
            data = resp.json()
            results = []
            for item in data.get("data", []):
                imgs = item.get("images", {})
                gif_url = imgs.get("downsized_medium", {}).get("url") or imgs.get("fixed_height", {}).get("url")
                preview_url = imgs.get("fixed_height_small", {}).get("url") or gif_url
                if gif_url:
                    results.append({
                        "id": item.get("id"),
                        "title": item.get("title", "GIF"),
                        "url": gif_url,
                        "preview": preview_url
                    })
            return jsonify({"ok": True, "gifs": results, "source": "giphy"})
    except Exception as ex:
        logging.info(f"Giphy API request error: {ex}")

    return jsonify({"ok": True, "gifs": [], "source": "error"})


# =============================================================================
# RUN
# =============================================================================

if __name__ == "__main__":
    # Start the sync worker thread
    start_sync_worker()
    
    debug = True
    socketio.run(app, host="0.0.0.0", port=10000, debug=debug, use_reloader=debug)
