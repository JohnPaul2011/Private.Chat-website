from flask import render_template, Flask, request, redirect, session, url_for, flash, jsonify, abort
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from colorama import init as init_color
import time, random, logging, os, re, hmac, hashlib, secrets, base64, struct, datetime, threading, uuid

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
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("FORCE_HTTPS", "1") == "1"
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
socketio = SocketIO(app, async_mode="threading", logger=False, engineio_logger=False,
                    ping_timeout=10, ping_interval=8)

BAD_USERNAMES = {"admin","server","system","moderator","host"}
rooms        = {}
room_passwords = {}
game_rooms   = {}   # code -> {type,diff,state,players,host,scores,poison_idx}
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

def gen_game_code():
    while True:
        c = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
        if c not in game_rooms: return c

def add_tile(board):
    empty = [i for i,v in enumerate(board) if v==0]
    if empty: board[_sysrand.choice(empty)] = 2 if _sysrand.random()<.9 else 4

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

def _admin_room_snapshot():
    with _state_lock:
        return {c: {"members": list(r["members"]), "message_count": len(r["messages"])}
                for c, r in rooms.items()}

def _push_admin_update():
    socketio.emit("admin_rooms_update", _admin_room_snapshot(), to="admin_channel")

@app.route("/admin")
def admin_panel():
    require_admin()
    return render_template("admin.html", rooms=_admin_room_snapshot())

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


# ─────────────────────────────── games route ────────────────────────────────
@app.route("/games")
def games_page():
    return render_template("game.html",
        username   = session.get("name",""),
        invite_code= request.args.get("code",""))


# ─────────────────────────────── chat socket ────────────────────────────────
MAX_FILE_B64 = int(5 * 1024 * 1024 * 1.4)  # 5MB raw budget, headroom for base64 overhead

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
    elif mtype == "file":
        payload = data.get("data","")
        filename = str(data.get("filename",""))[:255]
        mime = str(data.get("mime",""))[:100]
        if not isinstance(payload, str) or len(payload) > MAX_FILE_B64: return
        content = {"id":mid,"name":name,"type":"file","data":payload,
                   "filename":filename,"mime":mime,"timestamp":ts}
    else:
        text = data.get("data","")
        if not isinstance(text, str) or len(text) > 8000: return
        content = {"id":mid,"name":name,"type":"text","message":text,
                   "reply_to":data.get("reply_to"),"timestamp":ts}
    send(content, to=r)
    with _state_lock:
        rooms[r]["messages"].append(content)
        rooms[r].setdefault("seen", {})[mid] = {}
        if len(rooms[r]["messages"]) > 500:
            rooms[r]["messages"] = rooms[r]["messages"][-500:]
    _push_admin_update()


# ─────────────────────────── chunked file transfer ───────────────────────────
# Files/photos are streamed in pieces instead of one giant blocking payload:
# the sender splits the (already encrypted) blob into chunks and emits
# them one at a time; the server relays each chunk live to everyone else in
# the room (so they can show a progress bar / start reconstructing early)
# and buffers them to reassemble a single stored message once complete.
MAX_TRANSFER_CHUNKS = 300
MAX_CHUNK_LEN        = 250_000
TRANSFER_ID_RE       = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_file_transfers = {}   # transfer_id -> {room, name, filename, mime, total_chunks, chunks, received, started}

@socketio.on("file_chunk_start")
def file_chunk_start(data):
    r    = session.get("room")
    name = session.get("name","")
    if r not in rooms or not name or name not in rooms[r]["members"]: return
    if rate_limited(name): return
    transfer_id = str(data.get("transfer_id",""))
    total_chunks = data.get("total_chunks")
    if not TRANSFER_ID_RE.match(transfer_id): return
    if not isinstance(total_chunks, int) or not (0 < total_chunks <= MAX_TRANSFER_CHUNKS): return
    filename = str(data.get("filename",""))[:255]
    mime     = str(data.get("mime",""))[:100]
    ts       = time.strftime('%H:%M %p')
    with _state_lock:
        if transfer_id in _file_transfers: return   # id collision/replay, reject
        _file_transfers[transfer_id] = {
            "room": r, "name": name, "filename": filename, "mime": mime,
            "total_chunks": total_chunks, "chunks": [None]*total_chunks,
            "received": 0, "started": time.time(), "timestamp": ts
        }
    socketio.emit("file_chunk_meta", {
        "transfer_id": transfer_id, "name": name, "filename": filename,
        "mime": mime, "total_chunks": total_chunks, "timestamp": ts
    }, to=r, include_self=False)

@socketio.on("file_chunk")
def file_chunk(data):
    r    = session.get("room")
    name = session.get("name","")
    transfer_id = str(data.get("transfer_id",""))
    idx  = data.get("index")
    chunk = data.get("data","")
    if not isinstance(chunk, str) or len(chunk) > MAX_CHUNK_LEN: return
    with _state_lock:
        t = _file_transfers.get(transfer_id)
        if not t or t["room"] != r or t["name"] != name: return
        if not isinstance(idx, int) or not (0 <= idx < t["total_chunks"]): return
        if t["chunks"][idx] is None:
            t["received"] += 1
        t["chunks"][idx] = chunk
    socketio.emit("file_chunk", {"transfer_id": transfer_id, "index": idx, "data": chunk},
                   to=r, include_self=False)

@socketio.on("file_chunk_end")
def file_chunk_end(data):
    r    = session.get("room")
    name = session.get("name","")
    transfer_id = str(data.get("transfer_id",""))
    with _state_lock:
        t = _file_transfers.pop(transfer_id, None)
        if not t or t["room"] != r or t["name"] != name: return
        if t["received"] != t["total_chunks"] or any(c is None for c in t["chunks"]): return
        full_payload = "".join(t["chunks"])
        if len(full_payload) > MAX_FILE_B64: return
        content = {"id": transfer_id, "name": name, "type": "file", "data": full_payload,
                   "filename": t["filename"], "mime": t["mime"], "timestamp": t["timestamp"]}
        if r in rooms:
            rooms[r]["messages"].append(content)
            rooms[r].setdefault("seen", {})[transfer_id] = {}
            if len(rooms[r]["messages"]) > 500:
                rooms[r]["messages"] = rooms[r]["messages"][-500:]
    socketio.emit("file_chunk_complete", {
        "transfer_id": transfer_id, "id": transfer_id, "name": name,
        "timestamp": t["timestamp"]
    }, to=r)
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
    if r and name:
        with _state_lock:
            stale = [tid for tid,t in _file_transfers.items() if t["room"] == r and t["name"] == name]
            for tid in stale: _file_transfers.pop(tid, None)
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

    gc = session.get("game_code")
    gu = session.get("game_user")
    if gc and gu and gc in game_rooms:
        with _state_lock:
            gr = game_rooms.get(gc)
            if gr and gu in gr["players"]:
                gr["players"].remove(gu)
                empty = not gr["players"]
                if empty: del game_rooms[gc]
                players = gr["players"][:] if not empty else []
            else:
                empty = True; players = []
        if gr and not empty:
            emit("g_player_left",{"username":gu,"players":players}, to=f"game_{gc}")
        leave_room(f"game_{gc}")


# ─────────────────────────────── game sockets ───────────────────────────────
def _game_identity(data):
    """Only the session's own game identity is trusted; the client cannot claim to be anyone else."""
    code = session.get("game_code")
    username = session.get("game_user")
    return code, username

def _in_game(gr, username):
    return bool(gr) and username in gr["players"]

@socketio.on("g_create")
def g_create(data):
    username  = (data.get("username") or "").strip()
    gtype     = data.get("game","tictactoe")
    diff      = data.get("diff","easy")
    if gtype not in ("tictactoe","2048","poison"):
        emit("g_error",{"msg":"Unknown game type"}); return
    if not NAME_RE.match(username):
        emit("g_error",{"msg":"Username can only contain letters, numbers, - and _ (max 24 chars)"}); return
    code = gen_game_code()
    scores = {username:{"wins":0,"losses":0,"draws":0}}
    poison_idx = -1

    if gtype == "tictactoe":
        state = {"board":[None]*9,"turn":"X","winner":None,
                 "players":{"X":username,"O":None},"round":1}
    elif gtype == "2048":
        board=[0]*16; add_tile(board); add_tile(board)
        state = {"board":board,"score":0,"turnIndex":0,"players":[username]}
    else:
        cups = {"easy":6,"medium":4,"hard":3}.get(diff,4)
        poison_idx = _sysrand.randint(0,cups-1)
        state = {"numCups":cups,"alive":[username],"eliminated":[],
                 "pickerIndex":0,"picked":[],"roundNum":1,"gameOver":False,"winner":None}

    with _state_lock:
        game_rooms[code] = {"type":gtype,"diff":diff,"state":state,
                            "players":[username],"host":username,
                            "scores":scores,"poison_idx":poison_idx}
    session["game_code"] = code
    session["game_user"] = username
    join_room(f"game_{code}")
    emit("g_created",{"code":code,"state":state,"players":[username],
                      "scores":scores,"type":gtype,"diff":diff,"host":username})

@socketio.on("g_join")
def g_join(data):
    username = (data.get("username") or "").strip()
    code     = (data.get("code") or "").strip().upper()
    if not NAME_RE.match(username):
        emit("g_error",{"msg":"Username can only contain letters, numbers, - and _ (max 24 chars)"}); return
    if code not in game_rooms:
        emit("g_error",{"msg":"Game not found — check the code and try again"}); return
    with _state_lock:
        gr = game_rooms[code]
        if username in gr["players"] and session.get("game_user") != username:
            emit("g_error",{"msg":"That username is already taken in this game"}); return
        if username not in gr["players"]:
            gr["players"].append(username)
            gr["scores"].setdefault(username,{"wins":0,"losses":0,"draws":0})
            if gr["type"] == "tictactoe" and gr["state"]["players"]["O"] is None:
                gr["state"]["players"]["O"] = username
            elif gr["type"] == "2048":
                if username not in gr["state"]["players"]:
                    gr["state"]["players"].append(username)
            elif gr["type"] == "poison":
                if username not in gr["state"]["alive"] and username not in gr["state"]["eliminated"]:
                    gr["state"]["alive"].append(username)
        snapshot = {"state":gr["state"],"players":gr["players"][:],"scores":dict(gr["scores"]),
                    "type":gr["type"],"diff":gr["diff"],"host":gr["host"]}
    session["game_code"] = code
    session["game_user"] = username
    join_room(f"game_{code}")
    emit("g_joined",{"code":code, **snapshot})
    emit("g_player_joined",{"username":username,"players":snapshot["players"],
                            "state":snapshot["state"],"scores":snapshot["scores"]},
         to=f"game_{code}", include_self=False)

@socketio.on("g_move")
def g_move(data):
    code, username = _game_identity(data)
    if not code or code not in game_rooms: return
    gr = game_rooms[code]
    if not _in_game(gr, username): return

    if gr["type"] == "tictactoe":
        new_board = data.get("state", {}).get("board")
        old_state = gr["state"]
        old_board = old_state["board"]
        turn      = old_state["turn"]
        players   = old_state["players"]
        if old_state.get("winner"): return                    # game already over
        if players.get(turn) != username: return               # not your turn
        if not isinstance(new_board, list) or len(new_board) != 9: return
        # exactly one empty cell may flip to the current player's symbol
        diffs = [i for i in range(9) if old_board[i] != new_board[i]]
        if len(diffs) != 1: return
        i = diffs[0]
        if old_board[i] is not None or new_board[i] != turn: return
        for j in range(9):
            if j != i and new_board[j] != old_board[j]: return

        winner = _tictactoe_winner(new_board)
        gr["state"] = {**old_state, "board": new_board, "winner": winner,
                        "turn": ("O" if turn == "X" else "X")}
        emit("g_state",{"state":gr["state"],"scores":gr["scores"],"player":username},
             to=f"game_{code}", include_self=False)
        if winner:
            winner_username = None if winner == "draw" else players.get(winner)
            _apply_game_result(gr, winner_username)
            emit("g_result",{"winner":(winner_username or "draw"),
                             "scores":gr["scores"]}, to=f"game_{code}")
    else:
        # 2048 is single-player-per-board; only the state owner may push a move
        if username not in gr["state"].get("players",[]): return
        gr["state"] = data.get("state", gr["state"])
        emit("g_state",{"state":gr["state"],"scores":gr["scores"],"player":username},
             to=f"game_{code}", include_self=False)

def _tictactoe_winner(board):
    lines = [(0,1,2),(3,4,5),(6,7,8),(0,3,6),(1,4,7),(2,5,8),(0,4,8),(2,4,6)]
    for a,b,c in lines:
        if board[a] and board[a]==board[b]==board[c]:
            return board[a]
    if all(v is not None for v in board):
        return "draw"
    return None

def _apply_game_result(gr, winner_username):
    if winner_username:
        gr["scores"].setdefault(winner_username,{"wins":0,"losses":0,"draws":0})["wins"] += 1
        for p in gr["players"]:
            if p != winner_username:
                gr["scores"].setdefault(p,{"wins":0,"losses":0,"draws":0})["losses"] += 1
    else:
        for p in gr["players"]:
            gr["scores"].setdefault(p,{"wins":0,"losses":0,"draws":0})["draws"] += 1

@socketio.on("g_start")
def g_start(data):
    code, username = _game_identity(data)
    if not code or code not in game_rooms: return
    gr = game_rooms[code]
    if not _in_game(gr, username): return
    emit("g_started",{"state":gr["state"],"scores":gr["scores"],
                       "type":gr["type"],"diff":gr["diff"]},
         to=f"game_{code}")

@socketio.on("g_result")
def g_result(data):
    # Only used by 2048 (client computes game-over locally); tictactoe/poison results
    # are computed server-side and never trust this event's "winner" value.
    code, username = _game_identity(data)
    if not code or code not in game_rooms: return
    gr = game_rooms[code]
    if not _in_game(gr, username) or gr["type"] != "2048": return
    claimed_winner = data.get("winner")
    if claimed_winner not in (None, "draw", username): return  # can only report own result
    with _state_lock:
        _apply_game_result(gr, None if claimed_winner in (None,"draw") else claimed_winner)
    emit("g_result",{"winner":claimed_winner, "scores":gr["scores"]}, to=f"game_{code}")

@socketio.on("g_vote")
def g_vote(data):
    code, username = _game_identity(data)
    if not code or code not in game_rooms or not username: return
    gr = game_rooms[code]
    if not _in_game(gr, username): return
    with _state_lock:
        votes = gr.setdefault("votes", set())
        votes.add(username)
        total = len(gr["players"])
        count = len(votes)
    emit("g_vote_update",{"count":count,"total":total}, to=f"game_{code}")
    if count >= total:
        with _state_lock:
            gr["votes"] = set()
            if gr["type"] == "tictactoe":
                old_p = gr["state"]["players"]
                gr["state"] = {"board":[None]*9,"turn":"X","winner":None,
                               "players":{"X":old_p["O"],"O":old_p["X"]},
                               "round": gr["state"].get("round",1)+1}
            elif gr["type"] == "2048":
                board=[0]*16; add_tile(board); add_tile(board)
                gr["state"] = {"board":board,"score":0,"turnIndex":0,"players":gr["players"][:]}
            elif gr["type"] == "poison":
                cups = gr["state"]["numCups"]
                gr["poison_idx"] = _sysrand.randint(0, cups-1)
                gr["state"] = {"numCups":cups,"alive":gr["players"][:],"eliminated":[],
                               "pickerIndex":0,"picked":[],"roundNum":1,
                               "gameOver":False,"winner":None,"difficulty":gr["diff"]}
            new_state = gr["state"]
        emit("g_restart",{"state":new_state,"scores":gr["scores"]}, to=f"game_{code}")

@socketio.on("g_restart")
def g_restart(data):
    code, username = _game_identity(data)
    if not code or code not in game_rooms: return
    gr = game_rooms[code]
    if not _in_game(gr, username): return
    with _state_lock:
        if gr["type"] == "tictactoe":
            old_p = gr["state"]["players"]
            gr["state"] = {"board":[None]*9,"turn":"X","winner":None,
                           "players":{"X":old_p["O"],"O":old_p["X"]},
                           "round": gr["state"].get("round",1)+1}
        elif gr["type"] == "2048":
            board=[0]*16; add_tile(board); add_tile(board)
            gr["state"] = {"board":board,"score":0,"turnIndex":0,"players":gr["players"][:]}
        new_state = gr["state"]
    emit("g_restart",{"state":new_state,"scores":gr["scores"]}, to=f"game_{code}")

@socketio.on("g_poison_pick")
def g_poison_pick(data):
    code, username = _game_identity(data)
    cup = data.get("cup")
    if not code or code not in game_rooms or not username: return
    gr = game_rooms[code]
    if not _in_game(gr, username): return

    with _state_lock:
        st = gr["state"]
        if st.get("gameOver"): return
        if not isinstance(cup, int) or not (0 <= cup < st["numCups"]) or cup in st["picked"]: return
        alive = list(st["alive"])
        if username not in alive: return
        expected_picker = alive[st["pickerIndex"] % len(alive)]
        if expected_picker != username: return  # not your turn

        poisoned = (cup == gr["poison_idx"])
        picked   = st["picked"] + [cup]
        elim     = list(st["eliminated"])
        pi       = st["pickerIndex"]
        rnum     = st["roundNum"]
        game_over= False; winner=None

        if poisoned:
            elim.append(username)
            alive = [p for p in alive if p != username]
            if len(alive) <= 1:
                game_over = True; winner = alive[0] if alive else None
                if winner:
                    gr["scores"].setdefault(winner,{"wins":0,"losses":0,"draws":0})["wins"]+=1
            else:
                rnum+=1; picked=[]; pi=0
                gr["poison_idx"] = _sysrand.randint(0, st["numCups"]-1)
        else:
            pi = (st["pickerIndex"]+1) % len(alive)
            remaining = [i for i in range(st["numCups"]) if i not in picked]
            if len(remaining)==1: gr["poison_idx"] = remaining[0]

        new_state = {**st,"alive":alive,"eliminated":elim,
                     "pickerIndex":pi,"picked":picked,
                     "roundNum":rnum,"gameOver":game_over,"winner":winner}
        gr["state"] = new_state
        scores = dict(gr["scores"])

    emit("g_poison_result",{"cup":cup,"player":username,"poisoned":poisoned,
                            "state":new_state,"scores":scores},
         to=f"game_{code}")

@socketio.on("g_leave")
def g_leave(data):
    code, username = _game_identity(data)
    if code and username and code in game_rooms:
        with _state_lock:
            gr = game_rooms.get(code)
            if gr and username in gr["players"]:
                gr["players"].remove(username)
                empty = not gr["players"]
                if empty: del game_rooms[code]
                players = gr["players"][:] if not empty else []
            else:
                gr = None; empty = True; players = []
        if gr and not empty:
            emit("g_player_left",{"username":username,"players":players},
                 to=f"game_{code}", include_self=False)
    if code:
        leave_room(f"game_{code}")
    session.pop("game_code",None); session.pop("game_user",None)


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG","0") == "1"
    socketio.run(app, host="0.0.0.0", port=10000, debug=debug, use_reloader=debug)
