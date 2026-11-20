import ipaddress
import os
import re
import sqlite3
import subprocess
from flask import Flask, jsonify, request

app = Flask(__name__)

# Fix 1: Load secret key from environment variable instead of hardcoding
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable must be set before starting the app."
    )
app.secret_key = secret_key

# Strict RFC-1123 hostname pattern (prevents shell metacharacters and leading '-' flag injection)
HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_host(host: str) -> bool:
    """Validate that host is a legitimate IPv4/IPv6 address or RFC-1123 hostname."""
    if not host or host.startswith("-"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_REGEX.match(host))


@app.route("/user")
def get_user():
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"error": "Username parameter is required"}), 400

    # Fix 2: Parameterized SQL query with context manager to prevent SQL Injection
    with sqlite3.connect("users.db") as conn:
        cursor = conn.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (username,),
        )
        rows = cursor.fetchall()

    users = [{"id": row[0], "username": row[1]} for row in rows]
    return jsonify({"users": users}), 200


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1").strip()

    # Fix 3: Validate IP/hostname and execute argument list with shell=False
    if not is_valid_host(host):
        return jsonify({"error": "Invalid IP address or hostname"}), 400

    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", host],
            shell=False,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
        return jsonify({"host": host, "output": output}), 200
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping request timed out"}), 504
    except subprocess.CalledProcessError:
        return jsonify({"error": "Host unreachable"}), 502


if __name__ == "__main__":
    # Fix 4: Explicitly disable debug mode and bind to localhost
    app.run(host="127.0.0.1", port=5000, debug=False)
