from gevent import monkey
monkey.patch_all()

from flask import render_template, Flask, request, redirect, session, url_for, flash, jsonify, abort
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from colorama import init as init_color
import time, logging, os, re, hmac, hashlib, secrets, base64, struct, datetime, threading, uuid

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
    return render_template("index.html", username=session.get("name","Guest"))

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

def _admin_room_snapshot():
    with _state_lock:
        return {c: {"members": list(r["members"]), "message_count": len(r["messages"]),
                     "save_history": bool(r.get("save_history")),
                     "capturing": c in capturing_rooms,
                     "captured_count": len(captured_messages.get(c, []))}
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
    content = {"name":"Announcement","type":"text","message":text,
               "reply_to":None,"timestamp":ts}

    if target == "all":
        with _state_lock:
            codes = list(rooms.keys())
        for code in codes:
            with _state_lock:
                if code in rooms:
                    rooms[code]["messages"].append(content)
            send(content, to=code)
        flash(f"Announcement sent to {len(codes)} room(s).","info")
    else:
        with _state_lock:
            exists = target in rooms
            if exists: rooms[target]["messages"].append(content)
        if exists:
            send(content, to=target)
            flash(f"Announcement sent to {target}.","info")
        else:
            flash("Room not found.","error")
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
        return redirect(url_for("room"))
    return render_template("join.html", username=session.get("name","Guest"))

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
            rooms[code] = {"members":[], "messages":[], "save_history": save_history}
            room_passwords[code] = pw
        _push_admin_update()
        session.permanent = True
        session["room"] = code
        session["name"] = name
        return redirect(url_for("room"))
    return render_template("create.html", username=session.get("name","Guest"))

@app.route("/room")
def room():
    r = session.get("room")
    if not r or not session.get("name") or r not in rooms:
        return redirect("/")
    history = rooms[r]["messages"] if rooms[r].get("save_history") else []
    seen = rooms[r].get("seen", {}) if rooms[r].get("save_history") else {}
    return render_template("room.html", code=r, messages=history, username=session["name"], seen=seen)

@app.route("/logout")
def logout():
    session.pop("name",None)
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
    _push_admin_update()

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
            empty = removed and not rooms[r]["members"]
            if empty:
                del rooms[r]; room_passwords.pop(r,None)
            members = list(rooms[r]["members"]) if not empty and r in rooms else []
        if removed:
            send({"name":"System","type":"text","message":f"{name} left the room",
                  "timestamp":time.strftime('%H:%M %p')}, to=r)
            if not empty:
                socketio.emit("member_list", members, to=r)
            _push_admin_update()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG","0") == "1"
    socketio.run(app, host="0.0.0.0", port=10000, debug=debug, use_reloader=debug)
 