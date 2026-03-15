from gevent import monkey
monkey.patch_all()

from flask import render_template, Flask, request, redirect, session, url_for, flash, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from colorama import init as init_color, Fore
import time
import random
import logging

init_color(convert=True, strip=False)

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = "never_gonna_give_you_up"

socketio = SocketIO(app, async_mode="gevent", logger=False, engineio_logger=False)

BAD_USERNAMES = {"admin", "server", "system", "moderator", "host"}

pages = {"home": "index.html"}

rooms = {}
room_passwords = {}


def username_taken(name):
    n = name.lower()
    for room in rooms.values():
        for user in room["members"]:
            if user.lower() == n:
                return True
    return False


@app.route("/")
def index():
    logging.debug("Index page loaded")
    username = session.get("name", "Guest")
    return render_template(pages["home"], username=username)


@app.route("/lcr")
def list_chats_raw():
    logging.debug("USER requested room list")
    return jsonify({"rooms":list(room_passwords)})


@app.route("/clear/<id>")
def delete_chat(id):
    logging.debug(f"Clearing chat {id}")
    if session.get("name") == "jp-2f5bvi":
        room = rooms.get(id)
        if room:
            room["messages"] = []
    return redirect("/")


@app.route("/join", methods=["GET", "POST"])
def join():
    if request.method == "POST":

        name = request.form.get("name")
        code = request.form.get("code")
        password = request.form.get("password", "")

        logging.debug(f"Join attempt {name} -> {code}")

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

        logging.debug(f"Create room {code} by {name}")

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

    logging.debug(f"User entered room {room}")

    return render_template(
        "room.html",
        code=room,
        messages=rooms[room]["messages"],
        username=session["name"]
    )


@app.route("/logout")
def logout():

    logging.debug("User logout")

    session.pop("name", None)

    flash("You have been logged out.", "info")

    return redirect(url_for("index"))


@socketio.on("message")
def message(data):

    room = session.get("room")
    name = session.get("name")

    logging.debug(f"Message from {name} -> {room}")

    if name == "jp-2f5bvi":
        name = ""

    if room not in rooms:
        return

    content = {"name": name, "message": data["data"], "timestamp": time.strftime('%H:%M %p')}

    send(content, to=room)

    rooms[room]["messages"].append(content)


@socketio.on("connect")
def connect(auth=None):

    room = session.get("room")
    name = session.get("name")

    logging.debug(f"Socket connect {name}")

    if not room or not name or room not in rooms:
        return

    join_room(room)

    if name not in rooms[room]["members"]:
        rooms[room]["members"].append(name)

    send({"name": "System", "message": f"{name} entered the room", "timestamp": time.strftime('%H:%M %p')}, to=room)

    socketio.emit("member_list", rooms[room]["members"], to=room)


@socketio.on("disconnect")
def disconnect():

    room = session.get("room")
    name = session.get("name")

    logging.debug(f"Socket disconnect {name}")

    if room and name and room in rooms and name in rooms[room]["members"]:

        rooms[room]["members"].remove(name)

        send({"name": "System", "message": f"{name} left the room", "timestamp": time.strftime('%H:%M %p')}, to=room)

        socketio.emit("member_list", rooms[room]["members"], to=room)

        if not rooms[room]["members"]:

            del rooms[room]

            room_passwords.pop(room, None)


if __name__ == "__main__":

    socketio.run(app,
        host="0.0.0.0",
        port=10000,
        debug=True,
        use_reloader=True
    )

#if __name__ == "__main__":
#    print("Run with: gunicorn -k gthread -w 1 app:app")