import os
import sqlite3

import requests
from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "chirpy_secret_2024"  # Hardcoded weak secret key

DATABASE = os.environ.get("DATABASE_PATH", "/data/chirpy.db")


# ── DB helpers ─────────────────────────────────────────────────────────────────


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user',
            bio      TEXT    DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS posts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT    NOT NULL,
            content    TEXT    NOT NULL,
            is_private INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id    INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            content    TEXT    NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Plaintext passwords (intentional vuln: no hashing)
    seed_users = [
        ("admin", "admin",       "admin", "Site administrator."),
        ("alice", "password123", "user",  "Coffee enthusiast. Posts about life."),
        ("bob",   "123456",      "user",  "Just here for the memes."),
    ]
    for username, password, role, bio in seed_users:
        try:
            db.execute(
                "INSERT INTO users (username, password, role, bio) VALUES (?, ?, ?, ?)",
                (username, password, role, bio),
            )
        except sqlite3.IntegrityError:
            pass

    seed_posts = [
        (1, "Welcome to Chirpy!",    "Hello everyone — Chirpy is live. Enjoy your stay and post freely!", 0),
        (2, "My Secret Diary Entry", "Reminder to self: bank PIN is 4821. Do NOT share.",                 1),
        (3, "Hello World",           "Just joined Chirpy. Feels nice here!",                               0),
        (1, "Platform Rules",        "Be kind. No spam. Violations will be reviewed by admins.",           0),
    ]
    for user_id, title, content, is_private in seed_posts:
        try:
            db.execute(
                "INSERT INTO posts (user_id, title, content, is_private) VALUES (?, ?, ?, ?)",
                (user_id, title, content, is_private),
            )
        except Exception:
            pass

    db.commit()
    db.close()


# ── Helpers ────────────────────────────────────────────────────────────────────


def current_user():
    return session.get("user")


# ── Routes ─────────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    db = get_db()
    posts = db.execute(
        "SELECT posts.*, users.username FROM posts "
        "JOIN users ON posts.user_id = users.id "
        "WHERE is_private = 0 ORDER BY posts.id DESC"
    ).fetchall()
    return render_template("index.html", posts=posts)


# ── Authentication ─────────────────────────────────────────────────────────────


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # VULN: SQL Injection — user input interpolated directly into query string
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        db = get_db()
        user = db.execute(query).fetchone()

        if user:
            session["user"] = dict(user)
            session["role"] = user["role"]
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Username already taken."

    return render_template("register.html", error=error)


# ── Posts ──────────────────────────────────────────────────────────────────────


@app.route("/post/new", methods=["GET", "POST"])
def new_post():
    if not current_user():
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        is_private = 1 if request.form.get("is_private") else 0
        db = get_db()
        db.execute(
            "INSERT INTO posts (user_id, title, content, is_private) VALUES (?, ?, ?, ?)",
            (current_user()["id"], title, content, is_private),
        )
        db.commit()
        return redirect(url_for("index"))

    return render_template("new_post.html")


@app.route("/post/<int:post_id>")
def view_post(post_id):
    if not current_user():
        return redirect(url_for("login"))

    db = get_db()
    # VULN: IDOR — no ownership/privacy check; any authenticated user can read any private post
    post = db.execute(
        "SELECT posts.*, users.username FROM posts "
        "JOIN users ON posts.user_id = users.id WHERE posts.id = ?",
        (post_id,),
    ).fetchone()

    if not post:
        return render_template("404.html"), 404

    comments = db.execute(
        "SELECT comments.*, users.username FROM comments "
        "JOIN users ON comments.user_id = users.id WHERE post_id = ? ORDER BY id ASC",
        (post_id,),
    ).fetchall()

    return render_template("post.html", post=post, comments=comments)


@app.route("/post/<int:post_id>/comment", methods=["POST"])
def add_comment(post_id):
    if not current_user():
        return redirect(url_for("login"))

    content = request.form["content"]
    db = get_db()
    # VULN: Stored XSS — content saved and rendered unescaped in post.html
    db.execute(
        "INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)",
        (post_id, current_user()["id"], content),
    )
    db.commit()
    return redirect(url_for("view_post", post_id=post_id))


@app.route("/post/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    if not current_user():
        return redirect(url_for("login"))

    db = get_db()
    # VULN: Broken Access Control — no ownership check; any logged-in user can delete any post
    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    return redirect(url_for("index"))


# ── Search ─────────────────────────────────────────────────────────────────────


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []

    if q:
        db = get_db()
        # VULN: SQL Injection — query param interpolated directly into LIKE clause
        sql = (
            f"SELECT posts.*, users.username FROM posts "
            f"JOIN users ON posts.user_id = users.id "
            f"WHERE posts.title LIKE '%{q}%' AND is_private = 0"
        )
        results = db.execute(sql).fetchall()

    # VULN: Reflected XSS — raw query string wrapped in Markup and rendered in template
    return render_template("search.html", query=Markup(q), results=results)


# ── Profile ────────────────────────────────────────────────────────────────────


@app.route("/profile/<int:user_id>")
def profile(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return render_template("404.html"), 404

    posts = db.execute(
        "SELECT * FROM posts WHERE user_id = ? AND is_private = 0 ORDER BY id DESC",
        (user_id,),
    ).fetchall()

    return render_template("profile.html", profile_user=user, posts=posts)


@app.route("/profile/update", methods=["POST"])
def update_profile():
    if not current_user():
        return redirect(url_for("login"))

    bio = request.form.get("bio", "")
    # VULN: Mass Assignment / Privilege Escalation — 'role' accepted from user-supplied form data
    role = request.form.get("role", "user")

    db = get_db()
    db.execute(
        "UPDATE users SET bio = ?, role = ? WHERE id = ?",
        (bio, role, current_user()["id"]),
    )
    db.commit()

    # Refresh session with updated role
    user = db.execute("SELECT * FROM users WHERE id = ?", (current_user()["id"],)).fetchone()
    session["user"] = dict(user)
    session["role"] = user["role"]

    return redirect(url_for("profile", user_id=current_user()["id"]))


# ── Admin ──────────────────────────────────────────────────────────────────────


@app.route("/admin")
def admin():
    # VULN: Authorization relies entirely on session role, which is set from DB;
    # role can be escalated via the mass-assignment bug in /profile/update
    if session.get("role") != "admin":
        return render_template("403.html"), 403

    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    posts = db.execute(
        "SELECT posts.*, users.username FROM posts "
        "JOIN users ON posts.user_id = users.id ORDER BY posts.id DESC"
    ).fetchall()

    return render_template("admin.html", users=users, posts=posts)


# ── SSRF ───────────────────────────────────────────────────────────────────────


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    result = None
    error = None

    if url:
        try:
            # VULN: SSRF — arbitrary URL fetched with no allowlist or internal-IP filtering
            resp = requests.get(url, timeout=5, allow_redirects=True)
            result = resp.text[:8000]
        except Exception as exc:
            error = str(exc)

    return render_template("fetch.html", url=url, result=result, error=error)


# ── Bootstrap ──────────────────────────────────────────────────────────────────


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
