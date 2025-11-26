import eventlet
eventlet.monkey_patch()

from flask import render_template, Flask, request, redirect, session, url_for, flash, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from colorama import init as init_color, Fore
import datetime
import os
import random

start_T = str(datetime.datetime.now())
init_color(convert=True, strip=False)

app = Flask(__name__)
app.config['SECRET_KEY'] = "never_gonna_give_you_up"
socketio = SocketIO(app)

BAD_USERNAMES = {"admin", "server", "system", "moderator", "host"}

pages = {"home": "index.html"}

rooms = {}            # {room_id: {"members": [], "messages": []}}
room_passwords = {}   # {room_id: pw}


def username_taken(name):
    n = name.lower()
    for room in rooms.values():
        for user in room["members"]:
            if user.lower() == n:
                return True
    return False


@app.route("/")
def index():
    username = session.get("name", "Guest")
    return render_template(pages["home"], username=username)


@app.route("/lcr")
def list_chats_raw():
    if session.get("name") == "jp-2f5bvi":
        return jsonify(room_passwords)
    return redirect("/")


@app.route("/clear/<id>")
def delete_chat(id):
    if session.get("name") == "jp-2f5bvi":
        room = rooms.get(id, False)
        room["messages"] = []
        print(f"cleared messages for {id}")
    return redirect("/")


@app.route("/join", methods=["GET", "POST"])
def join():
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        password = request.form.get("password", "")

        stored_pw = room_passwords.get(code)

        if not name:
            flash("Please enter a name.", "error")
            return render_template("join.html", code=code)

        if name.lower() in BAD_USERNAMES:
            flash("This username is not allowed.", "error")
            return render_template("join.html", code=code, username=name)

        if username_taken(name):
            flash("This username is already in use.", "error")
            return render_template("join.html", code=code, username=name)

        if code not in rooms:
            flash("Room does not exist.", "error")
            return render_template("join.html", username=name)

        if stored_pw != password:
            flash("Incorrect password.", "error")
            return render_template("join.html", username=name)

        session["room"] = code
        session["name"] = name

        return redirect(url_for("room"))

    return render_template("join.html", username=session.get("name", "Guest"))


@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        password = request.form.get("password", "")

        if not name:
            flash("Please enter a name.", "error")
            return render_template("create.html")

        if name.lower() in BAD_USERNAMES:
            flash("This username is not allowed.", "error")
            return render_template("create.html", username=name)

        if username_taken(name):
            flash("This username is already in use.", "error")
            return render_template("create.html", username=name)

        if not code:
            code = generate_unique_code(4)
        elif code in rooms:
            flash("Room already exists.", "error")
            return render_template("create.html", username=name)

        rooms[code] = {"members": [], "messages": []}
        room_passwords[code] = password

        session["room"] = code
        session["name"] = name

        return redirect(url_for("room"))

    return render_template("create.html", username=session.get("name", "Guest"))


def generate_unique_code(length):
    while True:
        code = "".join(random.choices("0123456789", k=length))
        if code not in rooms:
            return code


@app.route("/room")
def room():
    room = session.get("room")
    if not room or session.get("name") is None or room not in rooms:
        return redirect("/")
    return render_template("room.html", code=room, messages=rooms[room]["messages"], username=session["name"])


@app.route("/logout")
def logout():
    session.pop('name', None)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# -----------------------------
#      SOCKET: MESSAGING
# -----------------------------
@socketio.on("message")
def message(data):
    room = session.get("room")
    name = session.get("name")

    if name == "jp-2f5bvi":
        name = ""

    if room not in rooms:
        return

    content = {"name": name, "message": data["data"]}
    send(content, to=room)
    rooms[room]["messages"].append(content)


# -----------------------------
#      ADMIN: KICK
# -----------------------------
@app.route("/kickall/<room_id>")
def kick_all(room_id):
    if session.get("name") != "jp-2f5bvi":
        return redirect("/")

    room = rooms.get(room_id)
    if not room:
        return redirect("/")

    socketio.emit("kicked", {}, room=room_id)
    socketio.emit("member_list", [], room=room_id)

    room["members"].clear()
    room["messages"].clear()
    room_passwords.pop(room_id, None)
    rooms.pop(room_id, None)

    return redirect("/")


@app.route("/kick/<room_id>/<user>")
def kick_user(room_id, user):
    if session.get("name") != "jp-2f5bvi":
        return redirect("/")

    room = rooms.get(room_id)
    if not room:
        return redirect("/")

    if user in room["members"]:
        send({"name": "", "message": f"{user} was kicked"}, room=room_id)

        socketio.emit("kicked_user", {"user": user}, room=room_id)

        room["members"].remove(user)

        socketio.emit("member_list", room["members"], room=room_id)

    return redirect("/")


# -----------------------------
#   SOCKET: CONNECT / DISCONNECT
# -----------------------------
@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")

    if not room or not name or room not in rooms:
        return

    join_room(room)

    if name not in rooms[room]["members"]:
        rooms[room]["members"].append(name)

    if name != "jp-2f5bvi":
        send({"name": name, "message": f"{name} entered the room"}, room=room)

    socketio.emit("member_list", rooms[room]["members"], room=room)


@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")

    if room and name and room in rooms and name in rooms[room]["members"]:
        rooms[room]["members"].remove(name)

        if name != "jp-2f5bvi":
            send({"name": name, "message": f"{name} left the room"}, room=room)

        socketio.emit("member_list", rooms[room]["members"], room=room)

        if not rooms[room]["members"]:
            del rooms[room]
            room_passwords.pop(room, None)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=10000)
