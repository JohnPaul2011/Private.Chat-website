import eventlet
eventlet.monkey_patch()

from flask import render_template, Flask, request, redirect, session, url_for, flash
from flask_socketio import SocketIO, send, join_room, leave_room
from colorama import init as init_color, Fore
import datetime
import os
import random

start_T = str(datetime.datetime.now())
init_color(convert=True, strip=False)

app = Flask(__name__)
app.config['SECRET_KEY'] = "never_gonna_give_you_up"
socketio = SocketIO(app)

pages = {"home": "index.html"}

rooms = {}            # {room_id: {"members": [], "messages": []}}
room_passwords = {}   # {room_id: plain_password}

@app.route("/")
def index():
    username = session.get("name", "Guest")
    if username is None:
        username = "Guest"
    return render_template(pages["home"], username=username)

@app.route("/join", methods=["GET", "POST"])
def join():
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        password = request.form.get("password")
        stored_pw = room_passwords.get(code)
        if not name:
            flash("Please enter a name.", "error")
            return render_template("join.html", code=code, username=name)
        if not code:
            flash("Please enter a room code.", "error")
            return render_template("join.html", code=code, username=name)
        if code not in rooms:
            flash("Room does not exist.", "error")
            return render_template("join.html", code=code, username=name)
        if stored_pw != password:
            flash("Incorrect password.", "error")
            return render_template("join.html", code=code, username=name)

        session["room"] = code
        session["name"] = name
        return redirect(url_for("room"))

    if session.get("name", "Guest") != "Guest":
        return render_template("join.html", username=session["name"])
    else:
        return render_template("join.html")

@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        password = request.form.get("password", False)

        if not name:
            flash("Please enter a name.", "error")
            return render_template("create.html", code=code, username=name)

        if not code:
            code = generate_unique_code(4)
        elif code in rooms:
            flash("Room already exists.", "error")
            return render_template("create.html", code=code, username=name)

        if not password:
            flash("Please enter a password for the room.", "error")
            return render_template("create.html", code=code, username=name)

        rooms[code] = {"members": [], "messages": []}
        room_passwords[code] = password  # store plain text password
        session["room"] = code
        session["name"] = name
        return redirect(url_for("room"))

    if session.get("name", "Guest") != "Guest":
        return render_template("create.html", username=session["name"])
    else:
        return render_template("create.html")

def generate_unique_code(length):
    while True:
        code = "".join(random.choices("0123456789", k=length))
        if code not in rooms:
            break
    return code

@app.route("/room")
def room():
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("index"))
    return render_template("room.html", code=room, messages=rooms[room]["messages"], username=session["name"])

@app.route("/logout")
def logout():
    session.pop('name', None)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return
    content = {
        "name": session.get("name"),
        "message": data["data"]
    }
    send(content, to=room)
    rooms[room]["messages"].append(content)

    # Print room id, plain password, and message
    pw_plain = room_passwords.get(room, "NO_PASS")
    print(f"{room} {pw_plain} {data['data']}")

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name or room not in rooms:
        return
    join_room(room)
    if name != "jp-2f5bvi":socketio.emit("notify", {"message": f"{name} has entered the room"}, room=room)
    if name not in rooms[room]["members"]:
        rooms[room]["members"].append(name)

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    if room and name and room in rooms and name in rooms[room]["members"]:
        rooms[room]["members"].remove(name)
        if name != "jp-2f5bvi":socketio.emit("notify", {"message": f"{name} has exited the room"}, room=room)
        if not rooms[room]["members"]:
            del rooms[room]
            room_passwords.pop(room, None)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=10000)
