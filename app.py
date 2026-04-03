from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, send
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import json, os
import pyotp
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'

# secure cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax'
)

# security headers
Talisman(app)

# rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"])

socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# load users
try:
    with open("users.json") as f:
        users_db = json.load(f)
except:
    users_db = {}

# brute force protection
login_attempts = {}

class User(UserMixin):
    def __init__(self, email):
        self.id = email

@login_manager.user_loader
def load_user(user_id):
    if user_id in users_db:
        return User(user_id)
    return None

# REGISTER
@app.route("/register", methods=["GET","POST"])
@limiter.limit("3 per minute")
def register():
    if request.method == "POST":
        email = request.form["user"]
        password = request.form["pass"]

        hashed = generate_password_hash(password)
        secret = pyotp.random_base32()

        users_db[email] = {
            "password": hashed,
            "2fa": secret,
            "role": "user"
        }

        if len(users_db) == 1:
            users_db[email]["role"] = "admin"

        with open("users.json","w") as f:
            json.dump(users_db, f)

        return redirect("/")

    return render_template("register.html")

# LOGIN
@app.route("/", methods=["GET","POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form["user"]
        password = request.form["pass"]
        ip = request.remote_addr

        login_attempts[ip] = login_attempts.get(ip, 0) + 1

        if login_attempts[ip] > 10:
            return "Too many attempts. Try later."

        if email in users_db and check_password_hash(users_db[email]["password"], password):
            session["tmp_user"] = email
            return redirect("/2fa")
        else:
            return "Wrong login"

    return render_template("login.html")

# 2FA
@app.route("/2fa", methods=["GET","POST"])
def twofa():
    if request.method == "POST":
        code = request.form["code"]
        email = session.get("tmp_user")

        if not email:
            return redirect("/")

        secret = users_db[email]["2fa"]
        totp = pyotp.TOTP(secret)

        if totp.verify(code):
            login_user(User(email))
            return redirect("/dashboard")
        else:
            return "Wrong code"

    return '''
    <body style="background:black;color:lime;text-align:center;">
    <h2>2FA Code</h2>
    <form method="POST">
    Code: <input name="code"><br>
    <button>Verify</button>
    </form>
    </body>
    '''

# DASHBOARD
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user.id)

# ADMIN PANEL
@app.route("/admin")
@login_required
def admin():
    user = current_user.id
    if users_db[user]["role"] != "admin":
        return "Access denied"

    return f"ADMIN PANEL<br>Users: {list(users_db.keys())}"

# RESET REQUEST
@app.route("/reset_request", methods=["GET","POST"])
@limiter.limit("2 per minute")
def reset_request():
    if request.method == "POST":
        email = request.form["user"]
        token = serializer.dumps(email)

        print(f"RESET LINK: http://localhost:5000/reset/{token}")
        return "Check terminal for reset link"

    return '''
    <form method="POST">
    Email: <input name="user">
    <button>Reset</button>
    </form>
    '''

# RESET PASSWORD
@app.route("/reset/<token>", methods=["GET","POST"])
def reset(token):
    try:
        email = serializer.loads(token, max_age=3600)
    except:
        return "Invalid token"

    if request.method == "POST":
        new_pass = request.form["pass"]
        users_db[email]["password"] = generate_password_hash(new_pass)

        with open("users.json","w") as f:
            json.dump(users_db, f)

        return redirect("/")

    return '''
    <form method="POST">
    New Password: <input name="pass">
    <button>Change</button>
    </form>
    '''

# LOGOUT
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

# CHAT
@socketio.on("message")
def handle_message(msg):
    send(msg, broadcast=True)

port = int(os.environ.get("PORT", 5000))

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=port)