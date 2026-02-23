"""
VulnBoard — Deliberately Vulnerable Flask Bulletin Board
=========================================================
This application is INTENTIONALLY INSECURE for penetration testing education.
Every vulnerability is by design. Do NOT deploy this in production.

Vulnerabilities included:
  - SQL Injection (login, search)
  - Reflected XSS (search)
  - Stored XSS (posts/comments rendered with |safe)
  - SSTI (profile bio via render_template_string)
  - IDOR (private posts, user API)
  - OS Command Injection (admin system panel)
  - Path Traversal (file download)
  - Broken Access Control (admin/users, admin/backup without auth)
  - Information Disclosure (plaintext passwords, DB backup download)
"""

import os
import sqlite3
import time
from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    jsonify,
    render_template_string,
    send_file,
    g,
)

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "super-secret-key-123"  # nosemgrep: python.flask.security.hardcoded-secret-key -- VULN: weak hardcoded secret key (intentional for session forgery testing)

DB_PATH = "/app/vulnboard.db"
UPLOAD_DIR = "/app/uploads"
START_TIME = time.time()

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def get_db():
    """Return a per-request sqlite3 connection stored on flask.g."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed data if the database does not exist."""
    if os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # -- schema ---------------------------------------------------------------
    cur.executescript(
        """
        CREATE TABLE users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            email      TEXT,
            bio        TEXT DEFAULT '',
            is_admin   INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE posts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            author_id  INTEGER REFERENCES users(id),
            is_private INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id    INTEGER REFERENCES posts(id),
            author_id  INTEGER REFERENCES users(id),
            content    TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # -- seed users -----------------------------------------------------------
    # VULN: passwords stored in plaintext (intentional)
    cur.execute(
        "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
        ("admin", "admin", "admin@vulnboard.local", 1),
    )
    cur.execute(
        "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
        ("user1", "password123", "user1@vulnboard.local", 0),
    )

    # -- seed posts -----------------------------------------------------------
    cur.execute(
        "INSERT INTO posts (title, content, author_id, is_private) VALUES (?, ?, ?, ?)",
        (
            "Welcome to VulnBoard!",
            "This is the official bulletin board for our team. Feel free to share updates, ask questions, and collaborate.",
            1,
            0,
        ),
    )
    cur.execute(
        "INSERT INTO posts (title, content, author_id, is_private) VALUES (?, ?, ?, ?)",
        (
            "Server Maintenance Scheduled",
            "We will be performing server maintenance this Saturday from 02:00 to 06:00 UTC. Expect brief downtime.",
            1,
            0,
        ),
    )
    cur.execute(
        "INSERT INTO posts (title, content, author_id, is_private) VALUES (?, ?, ?, ?)",
        (
            "New Project Kickoff",
            "Excited to announce the kickoff of Project Phoenix! Please check the shared drive for the initial requirements document.",
            2,
            0,
        ),
    )
    cur.execute(
        "INSERT INTO posts (title, content, author_id, is_private) VALUES (?, ?, ?, ?)",
        (
            "Office Snack Suggestions",
            "We are restocking the office kitchen next week. Reply with your snack requests! Current favorites: trail mix, granola bars, sparkling water.",
            2,
            0,
        ),
    )
    cur.execute(
        "INSERT INTO posts (title, content, author_id, is_private) VALUES (?, ?, ?, ?)",
        (
            "Q1 Security Review Summary",
            "The quarterly security review is complete. Overall posture has improved. Detailed findings are attached to the internal wiki.",
            1,
            0,
        ),
    )
    # Private post (for IDOR testing)
    cur.execute(
        "INSERT INTO posts (title, content, author_id, is_private) VALUES (?, ?, ?, ?)",
        (
            "CONFIDENTIAL: Admin Credentials Rotation",
            "Rotating production credentials next Monday. New root password will be shared via secure channel. Current temp password: Pr0d_T3mp!2026",
            1,
            1,
        ),
    )

    # -- seed comments --------------------------------------------------------
    cur.execute(
        "INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)",
        (1, 2, "Thanks for setting this up! Looks great."),
    )
    cur.execute(
        "INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)",
        (2, 2, "Will the API endpoints also be affected during maintenance?"),
    )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

BASE_CSS = """
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f5f5f5; color: #333; line-height: 1.6; }
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .container { max-width: 900px; margin: 0 auto; padding: 20px; }
    nav { background: #1e293b; padding: 12px 20px; display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }
    nav a { color: #e2e8f0; font-size: 14px; }
    nav .brand { font-weight: 700; font-size: 18px; color: #fff; }
    .card { background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    .card h2 { margin-bottom: 8px; }
    .meta { color: #666; font-size: 13px; margin-bottom: 8px; }
    form .field { margin-bottom: 14px; }
    form label { display: block; font-weight: 600; margin-bottom: 4px; }
    form input[type=text], form input[type=password], form input[type=email],
    form textarea { width: 100%; padding: 8px 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }
    form textarea { min-height: 100px; resize: vertical; }
    .btn { display: inline-block; padding: 8px 18px; background: #2563eb; color: #fff;
           border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
    .btn:hover { background: #1d4ed8; }
    .alert { padding: 10px 14px; border-radius: 4px; margin-bottom: 14px; }
    .alert-error { background: #fee2e2; color: #991b1b; }
    .alert-success { background: #d1fae5; color: #065f46; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #e5e7eb; }
    th { background: #f9fafb; font-weight: 600; }
    pre { background: #1e293b; color: #e2e8f0; padding: 14px; border-radius: 6px;
          overflow-x: auto; font-size: 13px; margin-top: 10px; }
    .comment { border-left: 3px solid #2563eb; padding-left: 12px; margin-bottom: 12px; }
</style>
"""


def nav_html():
    """Build navigation bar based on session state."""
    links = [
        '<a class="brand" href="/">VulnBoard</a>',
        '<a href="/">Home</a>',
        '<a href="/search">Search</a>',
    ]
    if "user_id" in session:
        links.append('<a href="/post/new">New Post</a>')
        links.append('<a href="/profile">Profile</a>')
        # Check admin
        db = get_db()
        user = db.execute(
            "SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if user and user["is_admin"]:
            links.append('<a href="/admin">Admin</a>')
        links.append('<a href="/logout">Logout</a>')
    else:
        links.append('<a href="/login">Login</a>')
        links.append('<a href="/register">Register</a>')
    return "<nav>" + " ".join(links) + "</nav>"


def page(title, body):
    """Wrap body HTML in a full page with nav and base CSS."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnBoard - {title}</title>{BASE_CSS}</head>
<body>{nav_html()}<div class="container">{body}</div></body></html>"""


# ---------------------------------------------------------------------------
# Routes — Board basics
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    db = get_db()
    posts = db.execute(
        "SELECT posts.*, users.username FROM posts "
        "JOIN users ON posts.author_id = users.id "
        "WHERE posts.is_private = 0 "
        "ORDER BY posts.created_at DESC"
    ).fetchall()
    items = ""
    for p in posts:
        items += f"""
        <div class="card">
            <h2><a href="/post/{p['id']}">{p['title']}</a></h2>
            <div class="meta">by {p['username']} &middot; {p['created_at']}</div>
            <p>{p['content'][:200]}{"..." if len(p['content']) > 200 else ""}</p>
        </div>"""
    body = f"<h1 style='margin:20px 0'>Bulletin Board</h1>{items}"
    return page("Home", body)


@app.route("/login", methods=["GET"])
def login_form():
    body = """
    <h1 style="margin:20px 0">Login</h1>
    <div class="card">
        <form method="post" action="/login">
            <div class="field"><label>Username</label>
                <input type="text" name="username" required></div>
            <div class="field"><label>Password</label>
                <input type="password" name="password" required></div>
            <button class="btn" type="submit">Login</button>
        </form>
    </div>"""
    return page("Login", body)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    # VULN: SQL Injection — user input interpolated directly into query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"  # nosemgrep: python.lang.security.audit.formatted-sql-query -- VULN: intentional SQL injection via f-string
    try:
        user = db.execute(query).fetchone()  # nosemgrep: python.flask.security.injection.tainted-sql-string -- VULN: intentional tainted SQL execution
    except Exception:
        user = None
    if user:
        session["user_id"] = user["id"]
        return redirect(url_for("index"))
    body = """
    <h1 style="margin:20px 0">Login</h1>
    <div class="alert alert-error">Invalid username or password.</div>
    <div class="card">
        <form method="post" action="/login">
            <div class="field"><label>Username</label>
                <input type="text" name="username" required></div>
            <div class="field"><label>Password</label>
                <input type="password" name="password" required></div>
            <button class="btn" type="submit">Login</button>
        </form>
    </div>"""
    return page("Login", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET"])
def register_form():
    body = """
    <h1 style="margin:20px 0">Register</h1>
    <div class="card">
        <form method="post" action="/register">
            <div class="field"><label>Username</label>
                <input type="text" name="username" required></div>
            <div class="field"><label>Password</label>
                <input type="password" name="password" required></div>
            <div class="field"><label>Email</label>
                <input type="email" name="email"></div>
            <button class="btn" type="submit">Register</button>
        </form>
    </div>"""
    return page("Register", body)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, password, email),
        )
        db.commit()
        return redirect(url_for("login_form"))
    except sqlite3.IntegrityError:
        body = """
        <h1 style="margin:20px 0">Register</h1>
        <div class="alert alert-error">Username already taken.</div>
        <div class="card">
            <form method="post" action="/register">
                <div class="field"><label>Username</label>
                    <input type="text" name="username" required></div>
                <div class="field"><label>Password</label>
                    <input type="password" name="password" required></div>
                <div class="field"><label>Email</label>
                    <input type="email" name="email"></div>
                <button class="btn" type="submit">Register</button>
            </form>
        </div>"""
        return page("Register", body)


@app.route("/post/<int:post_id>")
def view_post(post_id):
    db = get_db()
    # VULN: IDOR — no check on is_private; any post accessible by ID
    post = db.execute(  # nosemgrep: python.flask.security.injection.tainted-sql-string -- VULN: IDOR, no private check (parameterised query is fine here, the vuln is authorization)
        "SELECT posts.*, users.username FROM posts "
        "JOIN users ON posts.author_id = users.id WHERE posts.id = ?",
        (post_id,),
    ).fetchone()
    if not post:
        return page("Not Found", "<h1>Post not found</h1>"), 404

    comments = db.execute(
        "SELECT comments.*, users.username FROM comments "
        "JOIN users ON comments.author_id = users.id "
        "WHERE comments.post_id = ? ORDER BY comments.created_at",
        (post_id,),
    ).fetchall()

    comments_html = ""
    for c in comments:
        # VULN: Stored XSS — comment content rendered without escaping
        comments_html += f"""
        <div class="comment">
            <div class="meta">{c['username']} &middot; {c['created_at']}</div>
            <p>{c['content']}</p>
        </div>"""  # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2 -- VULN: stored XSS via unescaped comment content

    comment_form = ""
    if "user_id" in session:
        comment_form = f"""
        <h3 style="margin-top:20px">Add a Comment</h3>
        <form method="post" action="/post/{post_id}/comment">
            <div class="field"><textarea name="content" required placeholder="Write your comment..."></textarea></div>
            <button class="btn" type="submit">Post Comment</button>
        </form>"""

    # VULN: Stored XSS — post content rendered without escaping
    body = f"""
    <div class="card" style="margin-top:20px">
        <h1>{post['title']}</h1>
        <div class="meta">by {post['username']} &middot; {post['created_at']}</div>
        <div style="margin-top:12px">{post['content']}</div>
    </div>
    <h2 style="margin:16px 0 8px">Comments ({len(comments)})</h2>
    {comments_html}
    {comment_form}"""  # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2 -- VULN: stored XSS via unescaped post content
    return page(post["title"], body)


@app.route("/post/new", methods=["GET"])
def new_post_form():
    if "user_id" not in session:
        return redirect(url_for("login_form"))
    body = """
    <h1 style="margin:20px 0">New Post</h1>
    <div class="card">
        <form method="post" action="/post/new">
            <div class="field"><label>Title</label>
                <input type="text" name="title" required></div>
            <div class="field"><label>Content</label>
                <textarea name="content" required></textarea></div>
            <button class="btn" type="submit">Publish</button>
        </form>
    </div>"""
    return page("New Post", body)


@app.route("/post/new", methods=["POST"])
def new_post():
    if "user_id" not in session:
        return redirect(url_for("login_form"))
    title = request.form.get("title", "")
    content = request.form.get("content", "")
    db = get_db()
    cur = db.execute(
        "INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)",
        (title, content, session["user_id"]),
    )
    db.commit()
    return redirect(f"/post/{cur.lastrowid}")


@app.route("/post/<int:post_id>/comment", methods=["POST"])
def add_comment(post_id):
    if "user_id" not in session:
        return redirect(url_for("login_form"))
    content = request.form.get("content", "")
    db = get_db()
    db.execute(
        "INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)",
        (post_id, session["user_id"], content),
    )
    db.commit()
    return redirect(f"/post/{post_id}")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results_html = ""
    if q:
        db = get_db()
        # VULN: SQL Injection — user input interpolated directly into query
        # VULN: Reflected XSS — query term rendered back without escaping
        query = f"SELECT posts.*, users.username FROM posts JOIN users ON posts.author_id = users.id WHERE posts.title LIKE '%{q}%' OR posts.content LIKE '%{q}%' ORDER BY posts.created_at DESC"  # nosemgrep: python.lang.security.audit.formatted-sql-query -- VULN: intentional SQL injection via f-string
        try:
            results = db.execute(query).fetchall()  # nosemgrep: python.flask.security.injection.tainted-sql-string -- VULN: intentional tainted SQL execution
        except Exception:
            results = []
        if results:
            for r in results:
                results_html += f"""
                <div class="card">
                    <h2><a href="/post/{r['id']}">{r['title']}</a></h2>
                    <div class="meta">by {r['username']} &middot; {r['created_at']}</div>
                    <p>{r['content'][:200]}</p>
                </div>"""
        else:
            results_html = '<p style="margin-top:12px">No results found.</p>'

    # VULN: Reflected XSS — q rendered with |safe equivalent (direct interpolation)
    body = render_template_string(  # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2 -- VULN: reflected XSS via |safe on user-controlled search term
        """
    <h1 style="margin:20px 0">Search Posts</h1>
    <div class="card">
        <form method="get" action="/search">
            <div class="field"><label>Search term</label>
                <input type="text" name="q" value="{{ q }}" placeholder="Enter keywords..."></div>
            <button class="btn" type="submit">Search</button>
        </form>
    </div>
    {% if q %}
    <p style="margin:12px 0">Results for: <strong>{{ q | safe }}</strong></p>
    {{ results_html | safe }}
    {% endif %}
    """,
        q=q,
        results_html=results_html,
    )
    return page("Search", body)


# ---------------------------------------------------------------------------
# Routes — Admin
# ---------------------------------------------------------------------------


@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login_form"))
    db = get_db()
    user = db.execute(
        "SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if not user or not user["is_admin"]:
        return page("Forbidden", '<div class="alert alert-error">Admin access required.</div>'), 403

    post_count = db.execute("SELECT COUNT(*) AS cnt FROM posts").fetchone()["cnt"]
    user_count = db.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()["cnt"]
    uptime_secs = int(time.time() - START_TIME)
    uptime_str = f"{uptime_secs // 3600}h {(uptime_secs % 3600) // 60}m {uptime_secs % 60}s"

    body = f"""
    <h1 style="margin:20px 0">Admin Dashboard</h1>
    <div class="card">
        <table>
            <tr><th>Total Posts</th><td>{post_count}</td></tr>
            <tr><th>Total Users</th><td>{user_count}</td></tr>
            <tr><th>System Uptime</th><td>{uptime_str}</td></tr>
        </table>
        <div style="margin-top:16px">
            <a class="btn" href="/admin/users">Manage Users</a>
            <a class="btn" href="/admin/system" style="margin-left:8px">System Commands</a>
            <a class="btn" href="/admin/backup" style="margin-left:8px">Download Backup</a>
        </div>
    </div>"""
    return page("Admin", body)


@app.route("/admin/system")
def admin_system():
    if "user_id" not in session:
        return redirect(url_for("login_form"))
    db = get_db()
    user = db.execute(
        "SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if not user or not user["is_admin"]:
        return page("Forbidden", '<div class="alert alert-error">Admin access required.</div>'), 403

    cmd = request.args.get("cmd", "uptime")
    # VULN: OS Command Injection — user-supplied command executed directly
    output = os.popen(cmd).read()  # nosemgrep: python.lang.security.audit.dangerous-system-call.dangerous-system-call -- VULN: intentional OS command injection via os.popen

    body = f"""
    <h1 style="margin:20px 0">System Commands</h1>
    <div class="card">
        <form method="get" action="/admin/system">
            <div class="field"><label>Command</label>
                <input type="text" name="cmd" value="{cmd}"></div>
            <button class="btn" type="submit">Execute</button>
        </form>
        <h3 style="margin-top:16px">Output</h3>
        <pre>{output}</pre>
    </div>"""
    return page("System", body)


@app.route("/admin/users")
def admin_users():
    # VULN: Broken Access Control — no authentication or authorization check
    db = get_db()  # nosemgrep: python.flask.security.missing-authorization -- VULN: intentional broken access control, no login/admin check
    users = db.execute("SELECT id, username, email, password, is_admin, created_at FROM users").fetchall()
    rows = ""
    for u in users:
        # VULN: Information Disclosure — plaintext passwords displayed
        rows += f"""<tr>
            <td>{u['id']}</td>
            <td>{u['username']}</td>
            <td>{u['email']}</td>
            <td>{u['password']}</td>
            <td>{"Yes" if u['is_admin'] else "No"}</td>
            <td>{u['created_at']}</td>
        </tr>"""

    body = f"""
    <h1 style="margin:20px 0">User Management</h1>
    <div class="card">
        <table>
            <thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Password</th><th>Admin</th><th>Created</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""
    return page("Users", body)


@app.route("/admin/backup")
def admin_backup():
    # VULN: Broken Access Control + Info Disclosure — DB download with no auth check
    if not os.path.exists(DB_PATH):  # nosemgrep: python.flask.security.missing-authorization -- VULN: intentional broken access control, no login check for DB backup
        return page("Error", '<div class="alert alert-error">Database file not found.</div>'), 404
    return send_file(DB_PATH, as_attachment=True, download_name="vulnboard.db")


# ---------------------------------------------------------------------------
# Routes — API
# ---------------------------------------------------------------------------


@app.route("/api/posts")
def api_posts():
    db = get_db()
    # VULN: Information Disclosure — returns ALL posts including private ones
    posts = db.execute(  # nosemgrep: python.flask.security.missing-authorization -- VULN: intentional info disclosure, private posts exposed
        "SELECT posts.*, users.username FROM posts "
        "JOIN users ON posts.author_id = users.id "
        "ORDER BY posts.created_at DESC"
    ).fetchall()
    result = []
    for p in posts:
        result.append(
            {
                "id": p["id"],
                "title": p["title"],
                "content": p["content"],
                "author": p["username"],
                "is_private": p["is_private"],
                "created_at": p["created_at"],
            }
        )
    return jsonify(result)


@app.route("/api/user/<int:user_id>")
def api_user(user_id):
    db = get_db()
    # VULN: IDOR + Info Disclosure — any user data (including password) without auth
    user = db.execute(  # nosemgrep: python.flask.security.missing-authorization -- VULN: intentional IDOR, no auth check, password exposed
        "SELECT id, username, email, password, bio, is_admin, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(
        {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "password": user["password"],
            "bio": user["bio"],
            "is_admin": user["is_admin"],
            "created_at": user["created_at"],
        }
    )


# ---------------------------------------------------------------------------
# Routes — User profile
# ---------------------------------------------------------------------------


@app.route("/profile", methods=["GET"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("login_form"))
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()

    # VULN: SSTI — bio is rendered through Jinja2 template engine
    rendered_bio = render_template_string(user["bio"]) if user["bio"] else ""  # nosemgrep: python.flask.security.audit.render-template-string.render-template-string -- VULN: intentional SSTI via user-controlled bio field

    body = f"""
    <h1 style="margin:20px 0">Your Profile</h1>
    <div class="card">
        <table>
            <tr><th>Username</th><td>{user['username']}</td></tr>
            <tr><th>Email</th><td>{user['email']}</td></tr>
            <tr><th>Member since</th><td>{user['created_at']}</td></tr>
        </table>
        <h3 style="margin-top:16px">Bio</h3>
        <div style="padding:10px;background:#f9fafb;border-radius:4px;min-height:40px">{rendered_bio}</div>
        <h3 style="margin-top:20px">Update Bio</h3>
        <form method="post" action="/profile">
            <div class="field"><textarea name="bio" placeholder="Tell us about yourself...">{user['bio']}</textarea></div>
            <button class="btn" type="submit">Update</button>
        </form>
    </div>"""
    return page("Profile", body)


@app.route("/profile", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return redirect(url_for("login_form"))
    bio = request.form.get("bio", "")
    db = get_db()
    db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, session["user_id"]))
    db.commit()
    return redirect(url_for("profile"))


# ---------------------------------------------------------------------------
# Routes — File download
# ---------------------------------------------------------------------------


@app.route("/download")
def download():
    filename = request.args.get("file", "sample.txt")
    # VULN: Path Traversal — filename concatenated without sanitization
    filepath = "/app/uploads/" + filename  # nosemgrep: python.lang.security.audit.path-traversal.path-traversal -- VULN: intentional path traversal via unsanitised filename concatenation
    try:
        return send_file(filepath, as_attachment=True)  # nosemgrep: python.flask.security.audit.send-file-open.send-file-open -- VULN: intentional path traversal, serving arbitrary files
    except FileNotFoundError:
        return page("Not Found", '<div class="alert alert-error">File not found.</div>'), 404


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=80, debug=False)  # nosemgrep: python.flask.security.audit.app-run-param-config.app_run_params -- VULN: intentional bind to all interfaces for container access
