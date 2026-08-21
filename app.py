from gevent import monkey
monkey.patch_all()

from flask import render_template, Flask, request, redirect, session, url_for, flash, jsonify, abort
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from colorama import init as init_color
from pywebpush import webpush, WebPushException
from authlib.integrations.flask_client import OAuth
import time, logging, os, re, hmac, hashlib, secrets, base64, struct, datetime, threading, uuid, json
import requests as _requests

_sysrand = secrets.SystemRandom()

init_color(convert=True, strip=False)
logging.basicConfig(level=logging.INFO)

app   = Flask(__name__)
PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))
if PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=PROXY_HOPS, x_proto=1, x_host=0)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("FORCE_HTTPS", "0") == "1"
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
socketio = SocketIO(app, async_mode="gevent", logger=False, engineio_logger=False,
                    ping_timeout=10, ping_interval=8)

BAD_USERNAMES = {"admin","server","system","moderator","host"}
rooms        = {}
room_passwords = {}
_state_lock  = threading.Lock()

ADMIN_PASSWORD_HASH = os.environ.get(
    "ADMIN_PASSWORD_HASH",
    generate_password_hash(os.environ.get("ADMIN_PASSWORD", "changeme"))
)
TOTP_SECRET = os.environ.get("TOTP_SECRET", "")

_login_attempts = {}
LOGIN_MAX, LOGIN_WINDOW, LOGIN_LOCKOUT = 5, 300, 900
_used_totp_codes = {}
_msg_counters = {}
RATE_LIMIT_WINDOW, RATE_LIMIT_MAX = 5, 15
MAX_ROOMS = 1000
_create_attempts = {}
CREATE_MAX, CREATE_WINDOW = 10, 60

# ─────────────────────────────── Google OAuth ───────────────────────────────
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

oauth = OAuth(app)
google_oauth = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ─────────────────────────────── push notifications ─────────────────────────
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY  = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_CLAIMS      = {"sub": "mailto:admin@example.com"}

push_subscriptions = {}   # {google_id: subscription_dict} -- only linked Google accounts get push
connected_sids      = {}  # {room_code: set(names currently connected via socket)}

def send_push(google_id, title, body, room=None):
    if not google_id or not VAPID_PRIVATE_KEY:
        return
    with _state_lock:
        sub = push_subscriptions.get(google_id)
    if not sub:
        return
    try:
        webpush(
            subscription_info=sub,
            data=json.dumps({"title": title, "body": body, "room": room}),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims=dict(VAPID_CLAIMS),
        )
    except WebPushException as e:
        logging.info(f"Push failed, dropping subscription: {e}")
        with _state_lock:
            push_subscriptions.pop(google_id, None)


# ─────────────────────────────── Supabase (friends storage) ─────────────────
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

def sb_list_friends(owner_google_id):
    if not supabase_available(): return []
    try:
        r = _requests.get(
            f"{SUPABASE_URL}/rest/v1/chat_friends",
            headers=_supabase_headers(),
            params={"owner_google_id": f"eq.{owner_google_id}", "order": "created_at.desc"},
            timeout=8,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.info(f"Supabase list_friends failed: {e}")
        return []

def sb_add_friend(owner_google_id, owner_email, friend_google_id, friend_email, friend_display_name):
    if not supabase_available(): return False, "Storage not configured"
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
        if r.status_code >= 400:
            return False, r.text[:200]
        return True, None
    except Exception as e:
        return False, str(e)

def sb_remove_friend(owner_google_id, friend_google_id):
    if not supabase_available(): return False
    try:
        r = _requests.delete(
            f"{SUPABASE_URL}/rest/v1/chat_friends",
            headers=_supabase_headers(),
            params={"owner_google_id": f"eq.{owner_google_id}", "friend_google_id": f"eq.{friend_google_id}"},
            timeout=8,
        )
        return r.status_code < 400
    except Exception as e:
        logging.info(f"Supabase remove_friend failed: {e}")
        return False

def sb_find_user_by_email(email):
    """Look up a known google_id for an email, from anyone who has ever shown up as a friend row
    (owner or friend side) or currently has a push subscription. Best-effort only."""
    if not supabase_available() or not email: return None
    try:
        r = _requests.get(
            f"{SUPABASE_URL}/rest/v1/chat_friends",
            headers=_supabase_headers(),
            params={"friend_email": f"eq.{email}", "limit": 1},
            timeout=8,
        )
        r.raise_for_status()
        rows = r.json()
        if rows: return rows[0]["friend_google_id"]
    except Exception as e:
        logging.info(f"Supabase find_user_by_email failed: {e}")
    return None

def sb_get_profile(google_id):
    if not supabase_available() or not google_id: return None
    try:
        r = _requests.get(
            f"{SUPABASE_URL}/rest/v1/chat_profiles",
            headers=_supabase_headers(),
            params={"google_id": f"eq.{google_id}", "limit": 1},
            timeout=8,
        )
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None
    except Exception as e:
        logging.info(f"Supabase get_profile failed: {e}")
        return None

def sb_upsert_profile(google_id, email, display_name):
    if not supabase_available(): return False, "Storage not configured"
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
        if r.status_code >= 400:
            return False, r.text[:200]
        return True, None
    except Exception as e:
        return False, str(e)


# ─────────────────────────────── helpers ────────────────────────────────────
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,24}$")
CODE_RE = re.compile(r"^[A-Za-z0-9]{1,16}$")

def username_taken(name):
    n = name.lower()
    for r in rooms.values():
        for u in r["members"]:
            if u.lower() == n: return True
    return False

def gen_room_code(n=4):
    while True:
        c = "".join(secrets.choice("0123456789") for _ in range(n))
        if c not in rooms: return c

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
    if not session.get("is_admin"): abort(403)

def check_csrf():
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or token != session.get("csrf_token"): abort(403)

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = get_csrf_token

def totp_now(secret, step=30, digits=6, t=None):
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    counter = int((t or time.time()) // step)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

def verify_totp(secret, code):
    if not code or not re.match(r"^\d{6}$", code): return False
    now = time.time()
    with _state_lock:
        for k, exp in list(_used_totp_codes.items()):
            if exp < now: _used_totp_codes.pop(k, None)
        for skew in (-1, 0, 1):
            candidate = totp_now(secret, t=now + skew*30)
            if hmac.compare_digest(candidate, code):
                if code in _used_totp_codes: return False
                _used_totp_codes[code] = now + 90
                return True
    return False

def rate_limited(name):
    with _state_lock:
        now = time.time()
        bucket = _msg_counters.setdefault(name, [])
        bucket[:] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
        if len(bucket) >= RATE_LIMIT_MAX: return True
        bucket.append(now)
        return False

def create_rate_limited(key):
    with _state_lock:
        now = time.time()
        bucket = _create_attempts.setdefault(key, [])
        bucket[:] = [t for t in bucket if now - t < CREATE_WINDOW]
        if len(bucket) >= CREATE_MAX: return True
        bucket.append(now)
        return False


# ─────────────────────────────── chat routes ────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", username=session.get("name","Guest"),
                            google_signed_in=bool(session.get("google_id")))

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
        flash("Google sign-in failed.","error")
        return redirect(url_for("index"))
    if not userinfo or not userinfo.get("sub"):
        flash("Google sign-in failed.","error")
        return redirect(url_for("index"))
    session.permanent = True
    session["google_id"] = userinfo["sub"]
    session["google_email"] = userinfo.get("email","")

    profile = sb_get_profile(userinfo["sub"])
    if profile and profile.get("display_name"):
        session["preferred_name"] = profile["display_name"]
    elif userinfo.get("name"):
        # first sign-in: seed a profile from Google's name so it's editable in /account
        seed_name = re.sub(r"[^A-Za-z0-9_\- ]", "", userinfo["name"])[:24].strip()
        if seed_name:
            session["preferred_name"] = seed_name
            sb_upsert_profile(userinfo["sub"], userinfo.get("email",""), seed_name)

    flash("Signed in with Google. Pick a display name to continue.","info")
    return redirect(url_for("join"))

@app.route("/auth/google/logout")
def google_logout():
    gid = session.pop("google_id", None)
    session.pop("google_email", None)
    session.pop("preferred_name", None)
    if gid:
        with _state_lock:
            push_subscriptions.pop(gid, None)
    flash("Signed out of Google.","info")
    return redirect(url_for("index"))

@app.route("/vapid-public-key")
def vapid_public_key():
    return jsonify({"key": VAPID_PUBLIC_KEY})

@app.route("/save-subscription", methods=["POST"])
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
def remove_subscription():
    check_csrf()
    gid = session.get("google_id")
    if gid:
        with _state_lock:
            push_subscriptions.pop(gid, None)
    return jsonify({"ok": True})


# ─────────────────────────────── account dashboard ───────────────────────────
def require_google():
    if not session.get("google_id"):
        abort(401)

@app.route("/account")
def account():
    if not session.get("google_id"):
        flash("Sign in with Google to view your account.","error")
        return redirect(url_for("index"))
    gid = session["google_id"]
    friends = sb_list_friends(gid)
    profile = sb_get_profile(gid)
    preferred_name = (profile or {}).get("display_name") or session.get("preferred_name","")
    return render_template(
        "account.html",
        username=session.get("name","Guest"),
        google_email=session.get("google_email",""),
        google_id=gid,
        has_subscription=gid in push_subscriptions,
        friends=friends,
        supabase_available=supabase_available(),
        preferred_name=preferred_name,
    )

@app.route("/account/update-name", methods=["POST"])
def update_name():
    check_csrf()
    require_google()
    gid = session["google_id"]
    new_name = (request.form.get("display_name") or "").strip()
    if not NAME_RE.match(new_name):
        flash("Name must be 1-24 characters, letters/numbers/_/- only.","error")
        return redirect(url_for("account"))
    if new_name.lower() in BAD_USERNAMES:
        flash("That name isn't allowed.","error")
        return redirect(url_for("account"))
    ok, err = sb_upsert_profile(gid, session.get("google_email",""), new_name)
    if ok:
        session["preferred_name"] = new_name
        flash("Display name updated. It'll auto-fill next time you join or create a room.","info")
    else:
        flash(f"Couldn't update name: {err or 'unknown error'}","error")
    return redirect(url_for("account"))

@app.route("/account/friends/add", methods=["POST"])
def add_friend():
    check_csrf()
    require_google()
    gid = session["google_id"]
    email = (request.form.get("friend_email") or "").strip().lower()
    if not email or "@" not in email:
        flash("Enter a valid email address.","error")
        return redirect(url_for("account"))
    if email == (session.get("google_email") or "").lower():
        flash("You can't add yourself.","error")
        return redirect(url_for("account"))

    friend_gid = sb_find_user_by_email(email)
    ok, err = sb_add_friend(
        owner_google_id=gid,
        owner_email=session.get("google_email",""),
        friend_google_id=friend_gid or f"pending:{email}",
        friend_email=email,
        friend_display_name=None,
    )
    if ok:
        if friend_gid:
            flash(f"Added {email} as a friend.","info")
        else:
            flash(f"Added {email}. They'll be fully linked once they sign in with Google and are added back.","info")
    else:
        flash(f"Couldn't add friend: {err or 'unknown error'}","error")
    return redirect(url_for("account"))

@app.route("/account/friends/remove", methods=["POST"])
def remove_friend():
    check_csrf()
    require_google()
    gid = session["google_id"]
    friend_gid = request.form.get("friend_google_id","")
    if friend_gid and sb_remove_friend(gid, friend_gid):
        flash("Friend removed.","info")
    else:
        flash("Couldn't remove friend.","error")
    return redirect(url_for("account"))

@app.route("/account/test-push", methods=["POST"])
def test_push():
    check_csrf()
    require_google()
    gid = session["google_id"]
    if gid not in push_subscriptions:
        flash("No push subscription found. Open a room first to enable notifications.","error")
        return redirect(url_for("account"))
    send_push(gid, "Private.chat", "This is a test notification. Push is working.")
    flash("Test notification sent.","info")
    return redirect(url_for("account"))


@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        key = "admin:" + client_ip()
        if check_lockout(key):
            flash("Too many attempts. Try again later.","error")
            return render_template("admin_login.html", totp_required=bool(TOTP_SECRET))
        pw = request.form.get("password","")
        code = request.form.get("totp","")
        pw_ok = check_password_hash(ADMIN_PASSWORD_HASH, pw)
        totp_ok = (not TOTP_SECRET) or verify_totp(TOTP_SECRET, code)
        if pw_ok and totp_ok:
            record_success(key)
            session.permanent = True
            session["is_admin"] = True
            flash("Logged in.","info")
            return redirect(url_for("admin_panel"))
        record_failure(key)
        logging.warning(f"Failed admin login from {client_ip()}")
        flash("Incorrect password or code.","error")
    return render_template("admin_login.html", totp_required=bool(TOTP_SECRET))

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("index"))

capturing_rooms = set()          # room codes currently being live-captured
captured_messages = {}           # room code -> list of captured ciphertext messages

ROOM_EMPTY_GRACE = 30 * 60   # empty rooms stay visible/exportable to admin for 30 min before real cleanup

def _sweep_empty_rooms():
    now = time.time()
    with _state_lock:
        stale = [c for c, r in rooms.items()
                 if r.get("empty_since") and (now - r["empty_since"] > ROOM_EMPTY_GRACE)
                 and c not in capturing_rooms]   # never auto-sweep a room mid-capture
        for c in stale:
            rooms.pop(c, None)
            room_passwords.pop(c, None)
            captured_messages.pop(c, None)
            connected_sids.pop(c, None)

def _admin_room_snapshot():
    _sweep_empty_rooms()
    with _state_lock:
        return {c: {"members": list(r["members"]), "message_count": len(r["messages"]),
                     "save_history": bool(r.get("save_history")),
                     "capturing": c in capturing_rooms,
                     "captured_count": len(captured_messages.get(c, [])),
                     "empty": bool(r.get("empty_since"))}
                for c, r in rooms.items()}

def _push_admin_update():
    socketio.emit("admin_rooms_update", _admin_room_snapshot(), to="admin_channel")

@app.route("/admin")
def admin_panel():
    require_admin()
    return render_template("admin.html", rooms=_admin_room_snapshot())

@app.route("/admin/capture/start/<code>", methods=["POST"])
def admin_capture_start(code):
    require_admin(); check_csrf()
    with _state_lock:
        exists = code in rooms
        if exists:
            capturing_rooms.add(code)
            captured_messages.setdefault(code, [])
    if exists:
        flash(f"Started capturing {code}.","info")
        _push_admin_update()
    return redirect(url_for("admin_panel"))

@app.route("/admin/capture/stop/<code>", methods=["POST"])
def admin_capture_stop(code):
    require_admin(); check_csrf()
    with _state_lock:
        was_capturing = code in capturing_rooms
        capturing_rooms.discard(code)
    if was_capturing:
        flash(f"Stopped capturing {code}.","info")
        _push_admin_update()
    return redirect(url_for("admin_panel"))

@app.route("/admin/blobs/<code>")
def admin_blobs(code):
    require_admin()
    with _state_lock:
        stored = list(rooms[code]["messages"]) if code in rooms and rooms[code].get("save_history") else []
        captured = list(captured_messages.get(code, []))
    merged = {m["id"]: m for m in stored}
    for m in captured:
        merged.setdefault(m["id"], m)   # stored copy wins if a message exists in both
    combined = sorted(merged.values(), key=lambda m: m.get("timestamp",""))
    return jsonify({
        "room": code,
        "exported_at": time.strftime('%Y-%m-%d %H:%M:%S'),
        "note": "Message content is AES-256-GCM encrypted client-side. This is ciphertext only — no decryption key exists on this server.",
        "sources": {"stored_history": len(stored), "live_captured": len(captured)},
        "messages": combined
    })

@app.route("/admin/clear/<code>", methods=["POST"])
def admin_clear(code):
    require_admin(); check_csrf()
    with _state_lock:
        exists = code in rooms
        if exists: rooms[code]["messages"] = []
    if exists:
        flash(f"Cleared {code}.","info")
        _push_admin_update()
    return redirect(url_for("admin_panel"))

@app.route("/admin/kick/<code>/<user>", methods=["POST"])
def admin_kick(code, user):
    require_admin(); check_csrf()
    with _state_lock:
        room = rooms.get(code)
        kicked = bool(room and user in room["members"])
        members = None
        room_emptied = False
        if kicked:
            room["members"].remove(user)
            members = list(room["members"])
            if not room["members"]:
                del rooms[code]
                room_passwords.pop(code, None)
                room_emptied = True
    if kicked:
        socketio.emit("kicked_user", {"user": user}, to=code)
        if not room_emptied:
            socketio.emit("member_list", members, to=code)
        flash(f"Kicked {user} from {code}.","info")
        _push_admin_update()
    return redirect(url_for("admin_panel"))

@app.route("/admin/kickall/<code>", methods=["POST"])
def admin_kickall(code):
    require_admin(); check_csrf()
    with _state_lock:
        exists = code in rooms
        if exists:
            room_passwords.pop(code, None)
            rooms.pop(code, None)
            connected_sids.pop(code, None)
    if exists:
        socketio.emit("kicked", {}, to=code)
        flash(f"Kicked all from {code}.","info")
        _push_admin_update()
    return redirect(url_for("admin_panel"))

@app.route("/admin/announce", methods=["POST"])
def admin_announce():
    require_admin(); check_csrf()
    text = (request.form.get("announcement") or "").strip()
    target = request.form.get("target","all")   # "all" or a specific room code
    if not text:
        flash("Announcement text can't be empty.","error")
        return redirect(url_for("admin_panel"))
    if len(text) > 2000:
        flash("Announcement is too long.","error")
        return redirect(url_for("admin_panel"))

    ts = time.strftime('%H:%M %p')
    content = {"id": str(uuid.uuid4()), "name":"Announcement", "type":"text", "message":text,
               "reply_to":None, "timestamp":ts}

    if target == "all":
        with _state_lock:
            codes = list(rooms.keys())
        for code in codes:
            with _state_lock:
                if code in rooms and rooms[code].get("save_history"):
                    rooms[code]["messages"].append(content)
                google_map = dict(rooms.get(code, {}).get("google_map", {}))
                members = list(rooms.get(code, {}).get("members", []))
                online = connected_sids.get(code, set())
            socketio.emit("message", content, to=code)
            for member in members:
                if member not in online:
                    gid = google_map.get(member)
                    if gid:
                        send_push(gid, "Announcement", text[:120], room=code)
        flash(f"Announcement sent to {len(codes)} room(s).","info")
    else:
        with _state_lock:
            exists = target in rooms
            if exists and rooms[target].get("save_history"):
                rooms[target]["messages"].append(content)
            google_map = dict(rooms.get(target, {}).get("google_map", {})) if exists else {}
            members = list(rooms.get(target, {}).get("members", [])) if exists else []
            online = connected_sids.get(target, set())
        if exists:
            socketio.emit("message", content, to=target)
            for member in members:
                if member not in online:
                    gid = google_map.get(member)
                    if gid:
                        send_push(gid, "Announcement", text[:120], room=target)
            flash(f"Announcement sent to {target}.","info")
        else:
            flash("Room not found.","error")
    return redirect(url_for("admin_panel"))



@app.route("/admin/push-broadcast", methods=["POST"])
def admin_push_broadcast():
    require_admin(); check_csrf()
    title = (request.form.get("push_title") or "Private.chat").strip()[:80]
    body  = (request.form.get("push_body") or "").strip()
    if not body:
        flash("Push message can't be empty.","error")
        return redirect(url_for("admin_panel"))
    if len(body) > 500:
        flash("Push message is too long.","error")
        return redirect(url_for("admin_panel"))
    with _state_lock:
        targets = list(push_subscriptions.keys())
    sent = 0
    for gid in targets:
        send_push(gid, title, body)
        sent += 1
    flash(f"Push sent to {sent} subscribed device(s).","info")
    return redirect(url_for("admin_panel"))


@app.route("/join", methods=["GET","POST"])
def join():
    if request.method == "POST":
        check_csrf()
        name = request.form.get("name","").strip()
        code = request.form.get("code","").strip()
        pw   = request.form.get("password","")
        if not name:
            flash("Please enter a name.","error")
            return render_template("join.html", code=code)
        if not NAME_RE.match(name):
            flash("Username can only contain letters, numbers, - and _.","error")
            return render_template("join.html", code=code)
        if name.lower() in BAD_USERNAMES:
            flash("Username not allowed.","error")
            return render_template("join.html", code=code, username=name)
        if username_taken(name):
            flash("Username already in use.","error")
            return render_template("join.html", code=code, username=name)
        if code not in rooms:
            flash("Room does not exist.","error")
            return render_template("join.html", username=name)
        lock_key = "join:" + client_ip() + ":" + code
        if check_lockout(lock_key):
            flash("Too many attempts. Try again later.","error")
            return render_template("join.html", username=name)
        if not hmac.compare_digest(room_passwords.get(code) or "", pw or ""):
            record_failure(lock_key)
            flash("Incorrect password.","error")
            return render_template("join.html", username=name)
        record_success(lock_key)
        session.permanent = True
        session["room"] = code
        session["name"] = name
        if session.get("google_id"):
            with _state_lock:
                rooms[code].setdefault("google_map", {})[name] = session["google_id"]
        return redirect(url_for("room"))
    return render_template(
        "join.html",
        username=session.get("name") or session.get("preferred_name") or "Guest",
        google_signed_in=bool(session.get("google_id")),
    )

@app.route("/create", methods=["GET","POST"])
def create():
    if request.method == "POST":
        check_csrf()
        if create_rate_limited("create:" + client_ip()):
            flash("Too many rooms created recently. Try again in a minute.","error")
            return render_template("create.html")
        if len(rooms) >= MAX_ROOMS:
            flash("Server is at capacity. Try again later.","error")
            return render_template("create.html")
        name = request.form.get("name","").strip()
        code = request.form.get("code","").strip()
        pw   = request.form.get("password","")
        if not name:
            flash("Please enter a name.","error")
            return render_template("create.html")
        if not NAME_RE.match(name):
            flash("Username can only contain letters, numbers, - and _.","error")
            return render_template("create.html")
        if name.lower() in BAD_USERNAMES:
            flash("Username not allowed.","error")
            return render_template("create.html", username=name)
        if username_taken(name):
            flash("Username already in use.","error")
            return render_template("create.html", username=name)
        if not code: code = gen_room_code()
        elif not CODE_RE.match(code):
            flash("Room ID can only contain letters and numbers.","error")
            return render_template("create.html", username=name)
        elif code in rooms:
            flash("Room already exists.","error")
            return render_template("create.html", username=name)
        save_history = request.form.get("save_history") == "1"
        with _state_lock:
            rooms[code] = {"members":[], "messages":[], "save_history": save_history, "google_map": {}}
            room_passwords[code] = pw
            if session.get("google_id"):
                rooms[code]["google_map"][name] = session["google_id"]
        _push_admin_update()
        session.permanent = True
        session["room"] = code
        session["name"] = name
        return redirect(url_for("room"))
    return render_template(
        "create.html",
        username=session.get("name") or session.get("preferred_name") or "Guest",
        google_signed_in=bool(session.get("google_id")),
    )

@app.route("/room")
def room():
    r = session.get("room")
    if not r or not session.get("name") or r not in rooms:
        return redirect("/")
    history = rooms[r]["messages"] if rooms[r].get("save_history") else []
    seen = rooms[r].get("seen", {}) if rooms[r].get("save_history") else {}
    return render_template("room.html", code=r, messages=history, username=session["name"], seen=seen,
                            google_signed_in=bool(session.get("google_id")))

@app.route("/logout")
def logout():
    session.pop("name",None)
    session.pop("google_id",None)
    session.pop("google_email",None)
    flash("You have been logged out.","info")
    return redirect(url_for("index"))


# ─────────────────────────────── chat socket ────────────────────────────────
@socketio.on("message")
def message(data):
    r    = session.get("room")
    name = session.get("name","")
    if r not in rooms or not name: return
    if name not in rooms[r]["members"]: return
    if rate_limited(name): return
    ts  = time.strftime('%H:%M %p')
    mid = str(uuid.uuid4())
    mtype = data.get("type")
    if mtype == "voice":
        audio = data.get("audio","")
        mime  = str(data.get("mime",""))[:100]
        if not isinstance(audio, str) or len(audio) > 800_000: return
        content = {"id":mid,"name":name,"type":"voice","audio":audio,"mime":mime,
                   "duration":data.get("duration",0),"timestamp":ts}
    else:
        text = data.get("data","")
        if not isinstance(text, str) or len(text) > 8000: return
        content = {"id":mid,"name":name,"type":"text","message":text,
                   "reply_to":data.get("reply_to"),"timestamp":ts}
    send(content, to=r)
    with _state_lock:
        if rooms[r].get("save_history"):
            rooms[r]["messages"].append(content)
            rooms[r].setdefault("seen", {})[mid] = {}
            if len(rooms[r]["messages"]) > 500:
                rooms[r]["messages"] = rooms[r]["messages"][-500:]
        if r in capturing_rooms:
            captured_messages.setdefault(r, []).append(content)
        google_map = dict(rooms[r].get("google_map", {}))
        offline_members = [m for m in rooms[r]["members"]
                            if m != name and m not in connected_sids.get(r, set())]
    _push_admin_update()
    for member in offline_members:
        gid = google_map.get(member)
        if gid:
            send_push(gid, f"New message in {r}", f"{name} sent a message", room=r)

@socketio.on("latency_ping")
def latency_ping(data):
    # simple RTT echo so the client can measure its own round-trip time; nothing stored server-side
    emit("latency_pong", {"t": data.get("t")})

@socketio.on("report_latency")
def report_latency(data):
    r    = session.get("room")
    name = session.get("name","")
    if r not in rooms or not name or name not in rooms[r]["members"]: return
    ms = data.get("ms")
    if not isinstance(ms, (int, float)) or ms < 0 or ms > 60000: return
    socketio.emit("member_latency", {"name": name, "ms": round(ms)}, to=r)

@socketio.on("typing")
def typing(data):
    r    = session.get("room")
    name = session.get("name","")
    if r not in rooms or not name or name not in rooms[r]["members"]: return
    socketio.emit("typing", {"name": name, "active": bool(data.get("active"))}, to=r, include_self=False)

@socketio.on("mark_seen")
def mark_seen(data):
    r    = session.get("room")
    name = session.get("name","")
    if r not in rooms or not name: return
    ids = data.get("ids", [])
    if not isinstance(ids, list): return
    ts = time.time()
    updates = []
    with _state_lock:
        seen_map = rooms[r].setdefault("seen", {})
        total_others = max(len(rooms[r]["members"]) - 1, 0)
        for mid in ids[:100]:
            if not isinstance(mid, str): continue
            entry = seen_map.setdefault(mid, {})
            if name in entry: continue        # already recorded
            entry[name] = ts
            all_seen = len(entry) >= total_others and total_others > 0
            updates.append({"id": mid, "seen_by": dict(entry), "all_seen": all_seen})
    for u in updates:
        socketio.emit("seen_update", u, to=r)

@socketio.on("connect")
def connect(auth=None):
    if session.get("is_admin"):
        join_room("admin_channel")
        emit("admin_rooms_update", _admin_room_snapshot())

    r    = session.get("room")
    name = session.get("name")
    if not r or not name or r not in rooms: return
    join_room(r)
    with _state_lock:
        if name not in rooms[r]["members"]: rooms[r]["members"].append(name)
        rooms[r].pop("empty_since", None)
        connected_sids.setdefault(r, set()).add(name)
        members = list(rooms[r]["members"])
    send({"name":"System","type":"text","message":f"{name} entered the room",
          "timestamp":time.strftime('%H:%M %p')}, to=r)
    socketio.emit("member_list", members, to=r)
    _push_admin_update()

@socketio.on("disconnect")
def disconnect():
    r    = session.get("room")
    name = session.get("name")
    if r and name and r in rooms:
        with _state_lock:
            removed = name in rooms[r]["members"]
            if removed: rooms[r]["members"].remove(name)
            connected_sids.get(r, set()).discard(name)
            empty = removed and not rooms[r]["members"]
            if empty:
                rooms[r]["empty_since"] = time.time()   # kept around briefly for admin export, see ROOM_EMPTY_GRACE
                connected_sids.pop(r, None)
            members = list(rooms[r]["members"]) if r in rooms else []
        if removed:
            send({"name":"System","type":"text","message":f"{name} left the room",
                  "timestamp":time.strftime('%H:%M %p')}, to=r)
            if not empty:
                socketio.emit("member_list", members, to=r)
            _push_admin_update()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG","0") == "1"
    socketio.run(app, host="0.0.0.0", port=10000, debug=debug, use_reloader=debug)
 