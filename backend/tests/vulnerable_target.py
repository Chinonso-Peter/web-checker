"""Intentionally vulnerable app used ONLY for testing the Web Checker locally.

Run on port 5001:
    venv/bin/python backend/tests/vulnerable_target.py

It exposes SQLi, XSS, broken access control, crypto and auth weaknesses so the
Web Checker scanner can be validated without scanning a third-party site.
"""
from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/")
def index():
    resp = make_response(
        "<html><body><h1>Demo App</h1>"
        '<a href="/search">Search</a> | '
        '<a href="/login">Login</a> | '
        '<a href="/admin">Admin</a>'
        "</body></html>"
    )
    resp.set_cookie("session", "demo-session", httponly=False, secure=False)
    return resp


@app.route("/search", methods=["GET", "POST"])
def search():
    """Vulnerable endpoint: SQLi sink + reflected-XSS sink."""
    q = request.args.get("q", "")
    if "'" in q:
        query = "SELECT * FROM users WHERE username = '" + q + "'"
        body = (
            f'<html><body><h1>Search</h1><form method="get" action="/search">'
            f'  <input name="q" type="text" />'
            f'  <button type="submit">Search</button>'
            f"</form>"
            f"<p>SQL syntax error near {query}: 1</p></body></html>"
        )
    else:
        body = (
            f'<html><body><h1>Search</h1><form method="get" action="/search">'
            f'  <input name="q" type="text" />'
            f'  <button type="submit">Search</button>'
            f"</form>"
            f"<p>Results for: {q}</p></body></html>"
        )
    resp = make_response(body)
    resp.set_cookie("session", "demo-session", httponly=False, secure=False)
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    resp = make_response(
        '<html><body><h1>Login</h1>'
        '<form method="post" action="/login">'
        '  <input name="username" type="text" />'
        '  <input name="password" type="password" />'
        '  <button type="submit">Login</button>'
        "</form></body></html>"
    )
    resp.set_cookie("session", "demo-session", httponly=False, secure=False)
    return resp


@app.route("/admin")
def admin():
    return "<h1>Admin Panel</h1><p>Sensitive configuration here.</p>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False, load_dotenv=False)