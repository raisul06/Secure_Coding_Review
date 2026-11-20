# Secure_Coding_Review

Secure coding review of an intentionally vulnerable Flask application: static analysis with Bandit, manual audit, and a patched version.

> **Warning:** `vulnerable_app.py` is deliberately insecure. Run it only on a local, isolated machine. Never deploy it.

## Contents

| File | Purpose |
|---|---|
| `vulnerable_app.py` | Flask app with 4 seeded flaws (hardcoded secret, SQL injection, command injection, debug mode) |
| `bandit_report.txt` | Bandit output for `vulnerable_app.py` |
| `AUDIT_REPORT.md` | Findings with CWE/OWASP mapping, severity, line numbers, PoC payloads and remediation |
| `secure_app.py` | Patched version |

## Reproduce

```bash
pip install bandit flask

or 

python3 -m venv venv
source venv/bin/activate
pip install flask bandit

# 1. Static analysis
bandit -r vulnerable_app.py -f txt -o bandit_report.txt
bandit -r secure_app.py          # expect no High/Medium results

# 2. Create a test database
python - <<'EOF'
import sqlite3
c = sqlite3.connect("users.db")
c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
c.executemany("INSERT INTO users(username, password) VALUES(?, ?)", [("alice", "pw1"), ("bob", "pw2")])
c.commit()
EOF

# 3. Try the exploits on the vulnerable app
python vulnerable_app.py
curl "http://127.0.0.1:5000/user?username=%27%20OR%20%271%27%3D%271"
curl "http://127.0.0.1:5000/ping?host=127.0.0.1%3Bid"

# 4. Run the patched app (stop the other app first)
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python secure_app.py
```

## Findings at a glance

| # | Flaw | Line | CWE | OWASP 2021 | Fix |
|---|---|---|---|---|---|
| 1 | Hardcoded secret | 7 | 798 | A07 | Load from `FLASK_SECRET_KEY` |
| 2 | SQL injection | 14 | 89 | A03 | Parameterized query |
| 3 | Command injection | 22 | 78 | A03 | Argument list, `shell=False`, input validation |
| 4 | Debug mode | 26 | 489 | A05 | `debug=False` |

See `AUDIT_REPORT.md` for details.

Created by [MD Raisul Fahad](https://github.com/raisul06) ·
