import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)
app.secret_key = "hardcoded_super_secret_key"  # Flaw 1: Hardcoded secret


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    # Flaw 2: SQL Injection via string formatting
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    result = conn.execute(query).fetchall()
    return str(result)


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # Flaw 3: OS Command Injection via shell=True
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output


if __name__ == "__main__":
    app.run(debug=True)  # Flaw 4: Debug mode enabled in production
