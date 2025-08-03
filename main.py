import sqlite3
from flask import render_template, Flask, request, redirect, session, url_for, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, send, leave_room, join_room
import logging
from colorama import init as init_color
from colorama import Fore
import datetime
import os
import random

localhost_ip = "127.0.0.1"

start_T = str(datetime.datetime.now())
init_color(convert=True, strip=False)

app = Flask(__name__)
app.config['SECRET_KEY'] = "never_gonna_give_you_up"
socketio = SocketIO(app)
logging.basicConfig(level=logging.DEBUG, format=Fore.BLUE+'[%(asctime)s]'+Fore.RESET+' [%(levelname)s] '+Fore.GREEN+':'+Fore.RESET+' %(message)s')

pages = {"home": "index.html"}

# DB setup
def init_db():
    if not os.path.exists("data.db"):
        conn = sqlite3.connect("data.db")
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

init_db()

rooms = {}            # {room_id: {"members": 0, "messages": []}}
room_passwords = {}   # {room_id: password}

def handle_disconnect(flask_context=True):
    room = session.get("room")
    name = session.get("name")
    if room and name:
        if not flask_context:
            leave_room(room)
        if room in rooms and name in rooms[room]["members"]:
            rooms[room]["members"].remove(name)
            if not rooms[room]["members"]:
                del rooms[room]
                room_passwords.pop(room, None)


@app.route("/")
def index():
    
    username = session.get("name", "Guest")
    if username == None: username = "Guest"
    return render_template(pages["home"], username=username)

@app.route("/disconnect_route")
def disconnect_route():
    handle_disconnect()
    session["room"] = None
    return redirect(url_for("index"))


@app.route("/join", methods=["GET", "POST"])
def join():
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        password = request.form.get("password")
        hashed = room_passwords.get(code)
        if not name:
            flash("Please enter a name.","error")
            return render_template("join.html", code=code, username=name)
        if not code:
            flash("Please enter a room code.","error")
            return render_template("join.html", code=code, username=name)
        if code not in rooms:
            flash("Room does not exist.","error")
            return render_template("join.html", code=code, username=name)
        
        if not hashed or not check_password_hash(hashed, password):
            flash("Incorrect password.", "error")
            return render_template("join.html", code=code, username=name)


        session["room"] = code
        session["name"] = name
        return redirect(url_for("room"))

    if session.get("name","Guest") != "Guest": return render_template("create.html", username=session["name"])
    else:  return render_template("create.html")

@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        password = request.form.get("password",False)
        print(len(password),password)
        if not name:
            flash("Please enter a name.", "error")
            return render_template("create.html", code=code, username=name)

        if not code:
            code = generate_unique_code(4)
            
        elif code in rooms:
            flash("Room already exists.", "error")
            return render_template("create.html", code=code, username=name)   
        
        if password == False:
            flash("Please enter a password for the room.", "error")
            return render_template("create.html", code=code, username=name)

        hashed_pw = generate_password_hash(password)
        rooms[code] = {"members": [], "messages": []}
        room_passwords[code] = hashed_pw  # store hash
        session["room"] = code
        session["name"] = name
        return redirect(url_for("room"))

    if session.get("name","Guest") != "Guest": return render_template("create.html", username=session["name"])
    else:  return render_template("create.html")

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
    session.pop('username', None)
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

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name or room not in rooms:
        return
    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    rooms[room]["members"].append(name)

@socketio.on("disconnect")
def disconnect():
    handle_disconnect(False)
    


if __name__ == "__main__":
    print(f'\n * Running on http://{localhost_ip}:5500/')
    socketio.run(app, host=localhost_ip, port=5500)
