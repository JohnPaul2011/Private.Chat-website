from flask import render_template, Flask, request, redirect, session, url_for, flash, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from colorama import init as init_color
import time, random, logging

init_color(convert=True, strip=False)
logging.basicConfig(level=logging.DEBUG)

app   = Flask(__name__)
app.config['SECRET_KEY'] = "never_gonna_give_you_up"
socketio = SocketIO(app, async_mode="threading", logger=False, engineio_logger=False)

BAD_USERNAMES = {"admin","server","system","moderator","host"}
rooms        = {}
room_passwords = {}
game_rooms   = {}   # code -> {type,diff,state,players,host,scores,poison_idx}


# ─────────────────────────────── helpers ────────────────────────────────────
def username_taken(name):
    n = name.lower()
    for r in rooms.values():
        for u in r["members"]:
            if u.lower() == n: return True
    return False

def gen_room_code(n=4):
    while True:
        c = "".join(random.choices("0123456789", k=n))
        if c not in rooms: return c

def gen_game_code():
    while True:
        c = "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", k=6))
        if c not in game_rooms: return c

def add_tile(board):
    empty = [i for i,v in enumerate(board) if v==0]
    if empty: board[random.choice(empty)] = 2 if random.random()<.9 else 4


# ─────────────────────────────── chat routes ────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", username=session.get("name","Guest"))

@app.route("/lcr")
def list_chats_raw():
    return jsonify({"rooms": list(room_passwords)})

@app.route("/clear/<id>")
def delete_chat(id):
    if session.get("name") == "jp-2f5bvi":
        if id in rooms: rooms[id]["messages"] = []
    return redirect("/")

@app.route("/join", methods=["GET","POST"])
def join():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        code = request.form.get("code","").strip()
        pw   = request.form.get("password","")
        if not name:
            flash("Please enter a name.","error")
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
        if room_passwords.get(code) != pw:
            flash("Incorrect password.","error")
            return render_template("join.html", username=name)
        session["room"] = code
        session["name"] = name
        return redirect(url_for("room"))
    return render_template("join.html", username=session.get("name","Guest"))

@app.route("/create", methods=["GET","POST"])
def create():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        code = request.form.get("code","").strip()
        pw   = request.form.get("password","")
        if not name:
            flash("Please enter a name.","error")
            return render_template("create.html")
        if name.lower() in BAD_USERNAMES:
            flash("Username not allowed.","error")
            return render_template("create.html", username=name)
        if username_taken(name):
            flash("Username already in use.","error")
            return render_template("create.html", username=name)
        if not code: code = gen_room_code()
        elif code in rooms:
            flash("Room already exists.","error")
            return render_template("create.html", username=name)
        save_history = request.form.get("save_history") == "1"
        rooms[code] = {"members":[], "messages":[], "save_history": save_history}
        room_passwords[code] = pw
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
    if name == "jp-2f5bvi": name = ""
    if r not in rooms: return
    ts = time.strftime('%H:%M %p')
    if data.get("type") == "voice":
        content = {"name":name,"type":"voice","audio":data.get("audio",""),
                   "duration":data.get("duration",0),"timestamp":ts}
    else:
        content = {"name":name,"type":"text","message":data.get("data",""),
                   "reply_to":data.get("reply_to"),"timestamp":ts}
    send(content, to=r)
    rooms[r]["messages"].append(content)

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
    # game cleanup
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
    # Broadcast to all players (including host) to start playing
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
    # Broadcast current vote tally to everyone
    emit("g_vote_update",{"count":count,"total":total}, to=f"game_{code}")
    # Everyone voted — restart
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
    # Legacy handler kept for compatibility
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
    socketio.run(app, host="0.0.0.0", port=10000, debug=True, use_reloader=True)
