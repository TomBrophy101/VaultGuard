import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "hardcoded-insecure-secret-key"
DB_NAME = "vaultguard.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, email TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS vault_items (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, secret_data TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users (id))")
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        u, p, e = request.form["username"], request.form["password"], request.form["email"]
        conn = sqlite3.connect(DB_NAME)
        try:
            conn.execute(f"INSERT INTO users (username, password, email) VALUES ('{u}', '{p}', '{e}')")
            conn.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Username already exists."
        finally:
            conn.close()
    return render_template("register.html", error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = request.args.get("error")
    if request.method == "POST":
        u, p = request.form["username"], request.form["password"]
        conn = sqlite3.connect(DB_NAME)
        user = conn.execute(f"SELECT id, username FROM users WHERE username = '{u}' AND password = '{p}'").fetchone()
        conn.close()
        if user:
            session["user_id"], session["username"] = user[0], user[1]
            return redirect(url_for("dashboard"))
        return redirect(url_for("login", error=f"Invalid login attempt for user: {u}"))
    return render_template("login.html", error=error)

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB_NAME)
    if request.method == "POST":
        t, s = request.form["title"], request.form["secret_data"]
        conn.execute(f"INSERT INTO vault_items (user_id, title, secret_data) VALUES ({session['user_id']}, '{t}', '{s}')")
        conn.commit()
    q = request.args.get("q", "")
    sql = f"SELECT id, title, secret_data FROM vault_items WHERE user_id = {session['user_id']} AND title LIKE '%{q}%'" if q else f"SELECT id, title, secret_data FROM vault_items WHERE user_id = {session['user_id']}"
    items = conn.execute(sql).fetchall()
    conn.close()
    return render_template("dashboard.html", username=session["username"], items=items, search_query=q)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
