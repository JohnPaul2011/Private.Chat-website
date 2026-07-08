from flask import render_template, Flask, request, redirect, session, url_for, flash, jsonify, abort
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from colorama import init as init_color
import time, random, logging, os, re, hmac, hashlib, secrets, base64, struct, datetime, threading

init_color(convert=True, strip=False)
logging.basicConfig(level=logging.INFO)

app   = Flask(__name__)
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
    if empty: board[random.choice(empty)] = 2 if random.random()<.9 else 4

def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

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

@app.route("/admin")
def admin_panel():
    require_admin()
    room_data = {c: {"members": list(r["members"]), "message_count": len(r["messages"])} for c, r in rooms.items()}
    return render_template("admin.html", rooms=room_data)

@app.route("/admin/clear/<code>", methods=["POST"])
def admin_clear(code):
    require_admin(); check_csrf()
    if code in rooms:
        rooms[code]["messages"] = []
        flash(f"Cleared {code}.","info")
    return redirect(url_for("admin_panel"))

@app.route("/admin/kick/<code>/<user>", methods=["POST"])
def admin_kick(code, user):
    require_admin(); check_csrf()
    room = rooms.get(code)
    if room and user in room["members"]:
        socketio.emit("kicked_user", {"user": user}, to=code)
        room["members"].remove(user)
        socketio.emit("member_list", room["members"], to=code)
        flash(f"Kicked {user} from {code}.","info")
    return redirect(url_for("admin_panel"))

@app.route("/admin/kickall/<code>", methods=["POST"])
def admin_kickall(code):
    require_admin(); check_csrf()
    if code in rooms:
        socketio.emit("kicked", {}, to=code)
        room_passwords.pop(code, None)
        rooms.pop(code, None)
        flash(f"Kicked all from {code}.","info")
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
    return render_template("room.html", code=r, messages=history, username=session["name"])

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
@socketio.on("message")
def message(data):
    r    = session.get("room")
    name = session.get("name","")
    if r not in rooms or not name: return
    if rate_limited(name): return
    ts = time.strftime('%H:%M %p')
    if data.get("type") == "voice":
        audio = data.get("audio","")
        if not isinstance(audio, str) or len(audio) > 3_000_000: return
        content = {"name":name,"type":"voice","audio":audio,
                   "duration":data.get("duration",0),"timestamp":ts}
    else:
        text = data.get("data","")
        if not isinstance(text, str) or len(text) > 8000: return
        content = {"name":name,"type":"text","message":text,
                   "reply_to":data.get("reply_to"),"timestamp":ts}
    send(content, to=r)
    rooms[r]["messages"].append(content)
    if len(rooms[r]["messages"]) > 500:
        rooms[r]["messages"] = rooms[r]["messages"][-500:]

@socketio.on("connect")
def connect(auth=None):
    r    = session.get("room")
    name = session.get("name")
    if not r or not name or r not in rooms: return
    join_room(r)
    if name not in rooms[r]["members"]: rooms[r]["members"].append(name)
    send({"name":"System","type":"text","message":f"{name} entered the room",
          "timestamp":time.strftime('%H:%M %p')}, to=r)
    socketio.emit("member_list", rooms[r]["members"], to=r)

@socketio.on("disconnect")
def disconnect():
    r    = session.get("room")
    name = session.get("name")
    if r and name and r in rooms and name in rooms[r]["members"]:
        rooms[r]["members"].remove(name)
        send({"name":"System","type":"text","message":f"{name} left the room",
              "timestamp":time.strftime('%H:%M %p')}, to=r)
        socketio.emit("member_list", rooms[r]["members"], to=r)
        if not rooms[r]["members"]:
            del rooms[r]; room_passwords.pop(r,None)
    gc = session.get("game_code")
    gu = session.get("game_user")
    if gc and gc in game_rooms and gu:
        gr = game_rooms[gc]
        if gu in gr["players"]: gr["players"].remove(gu)
        if not gr["players"]: del game_rooms[gc]
        else:
            emit("g_player_left",{"username":gu,"players":gr["players"]}, to=f"game_{gc}")
        leave_room(f"game_{gc}")


# ─────────────────────────────── game sockets ───────────────────────────────
@socketio.on("g_create")
def g_create(data):
    username  = data.get("username","").strip()
    gtype     = data.get("game","tictactoe")
    diff      = data.get("diff","easy")
    if not username:
        emit("g_error",{"msg":"Enter a username"}); return
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
        poison_idx = random.randint(0,cups-1)
        state = {"numCups":cups,"alive":[username],"eliminated":[],
                 "pickerIndex":0,"picked":[],"roundNum":1,"gameOver":False,"winner":None}

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
    username = data.get("username","").strip()
    code     = data.get("code","").strip().upper()
    if code not in game_rooms:
        emit("g_error",{"msg":"Game not found — check the code and try again"}); return
    gr = game_rooms[code]
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
    session["game_code"] = code
    session["game_user"] = username
    join_room(f"game_{code}")
    emit("g_joined",{"code":code,"state":gr["state"],"players":gr["players"],
                     "scores":gr["scores"],"type":gr["type"],
                     "diff":gr["diff"],"host":gr["host"]})
    emit("g_player_joined",{"username":username,"players":gr["players"],
                            "state":gr["state"],"scores":gr["scores"]},
         to=f"game_{code}", include_self=False)

@socketio.on("g_move")
def g_move(data):
    code = session.get("game_code") or data.get("code","")
    if code not in game_rooms: return
    gr = game_rooms[code]
    gr["state"] = data["state"]
    emit("g_state",{"state":data["state"],"scores":gr["scores"],"player":data.get("player","")},
         to=f"game_{code}", include_self=False)

@socketio.on("g_start")
def g_start(data):
    code = session.get("game_code") or data.get("code","")
    if code not in game_rooms: return
    gr = game_rooms[code]
    emit("g_started",{"state":gr["state"],"scores":gr["scores"],
                       "type":gr["type"],"diff":gr["diff"]},
         to=f"game_{code}")

@socketio.on("g_result")
def g_result(data):
    code = session.get("game_code") or data.get("code","")
    if code not in game_rooms: return
    gr = game_rooms[code]
    winner = data.get("winner")
    if winner and winner != "draw":
        gr["scores"].setdefault(winner,{"wins":0,"losses":0,"draws":0})["wins"] += 1
        for p in gr["players"]:
            if p != winner:
                gr["scores"].setdefault(p,{"wins":0,"losses":0,"draws":0})["losses"] += 1
    elif winner == "draw":
        for p in gr["players"]:
            gr["scores"].setdefault(p,{"wins":0,"losses":0,"draws":0})["draws"] += 1
    emit("g_result",{"winner":winner,"scores":gr["scores"]}, to=f"game_{code}")

@socketio.on("g_vote")
def g_vote(data):
    code = session.get("game_code") or data.get("code","")
    if code not in game_rooms: return
    gr = game_rooms[code]
    votes = gr.setdefault("votes", set())
    username = session.get("game_user","")
    votes.add(username)
    total = len(gr["players"])
    count = len(votes)
    emit("g_vote_update",{"count":count,"total":total}, to=f"game_{code}")
    if count >= total:
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
            gr["poison_idx"] = random.randint(0, cups-1)
            gr["state"] = {"numCups":cups,"alive":gr["players"][:],"eliminated":[],
                           "pickerIndex":0,"picked":[],"roundNum":1,
                           "gameOver":False,"winner":None,"difficulty":gr["diff"]}
        emit("g_restart",{"state":gr["state"],"scores":gr["scores"]}, to=f"game_{code}")

@socketio.on("g_restart")
def g_restart(data):
    code = session.get("game_code") or data.get("code","")
    if code not in game_rooms: return
    gr = game_rooms[code]
    if gr["type"] == "tictactoe":
        old_p = gr["state"]["players"]
        gr["state"] = {"board":[None]*9,"turn":"X","winner":None,
                       "players":{"X":old_p["O"],"O":old_p["X"]},
                       "round": gr["state"].get("round",1)+1}
    elif gr["type"] == "2048":
        board=[0]*16; add_tile(board); add_tile(board)
        gr["state"] = {"board":board,"score":0,"turnIndex":0,"players":gr["players"][:]}
    emit("g_restart",{"state":gr["state"],"scores":gr["scores"]}, to=f"game_{code}")

@socketio.on("g_poison_pick")
def g_poison_pick(data):
    code     = session.get("game_code") or data.get("code","")
    username = session.get("game_user") or data.get("username","")
    cup      = data.get("cup")
    if code not in game_rooms: return
    gr    = game_rooms[code]
    st    = gr["state"]
    poisoned = (cup == gr["poison_idx"])
    picked   = st["picked"] + [cup]
    alive    = list(st["alive"])
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
            gr["poison_idx"] = random.randint(0, st["numCups"]-1)
    else:
        pi = (st["pickerIndex"]+1) % len(alive)
        remaining = [i for i in range(st["numCups"]) if i not in picked]
        if len(remaining)==1: gr["poison_idx"] = remaining[0]

    new_state = {**st,"alive":alive,"eliminated":elim,
                 "pickerIndex":pi,"picked":picked,
                 "roundNum":rnum,"gameOver":game_over,"winner":winner}
    gr["state"] = new_state
    emit("g_poison_result",{"cup":cup,"player":username,"poisoned":poisoned,
                            "state":new_state,"scores":gr["scores"]},
         to=f"game_{code}")

@socketio.on("g_leave")
def g_leave(data):
    code     = session.get("game_code") or data.get("code","")
    username = session.get("game_user") or data.get("username","")
    if code in game_rooms:
        gr = game_rooms[code]
        if username in gr["players"]: gr["players"].remove(username)
        if not gr["players"]: del game_rooms[code]
        else:
            emit("g_player_left",{"username":username,"players":gr["players"]},
                 to=f"game_{code}", include_self=False)
    leave_room(f"game_{code}")
    session.pop("game_code",None); session.pop("game_user",None)


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG","0") == "1"
    socketio.run(app, host="0.0.0.0", port=10000, debug=debug, use_reloader=debug)
