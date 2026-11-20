# Security Code Audit Report — Flask Web Application

**Author:** MD Raisul Fahad  
**Target Application:** `vulnerable_app.py`  
**Language / Framework:** Python 3 / Flask  
**Audit Methodology:** Static Application Security Testing (SAST via Bandit) + Manual Line-by-Line Source Code Review  
**Remediated Deliverable:** `secure_app.py`

---

## Executive Summary

A hybrid static and manual security audit was conducted on `vulnerable_app.py`. The assessment identified **four critical/high-impact security vulnerabilities** spanning injection flaws, cryptographic secret exposure, and insecure production configuration.

| ID | Vulnerability | Line(s) | Bandit ID | CWE | OWASP Top 10 (2021) | Risk Severity |
|---|---|---|---|---|---|---|
| **VULN-01** | Hardcoded Flask Secret Key | Line 7 | `B105` | CWE-798 / CWE-321 | A02:2021 – Cryptographic Failures | **High** (Bandit: Low) |
| **VULN-02** | SQL Injection (SQLi) | Lines 15–16 | `B608` | CWE-89 | A03:2021 – Injection | **Critical** (Bandit: Medium) |
| **VULN-03** | OS Command Injection | Line 24 | `B602` | CWE-78 | A03:2021 – Injection | **Critical** (Bandit: High) |
| **VULN-04** | Flask Debug Mode Enabled | Line 29 | `B201` | CWE-489 / CWE-94 | A05:2021 – Security Misconfiguration | **High** (Bandit: High) |

> **Note on Severity Rating:** While Bandit classifies `B105` as Low and `B608` as Medium based on static confidence heuristics, manual risk assessment elevates **VULN-01** to **High** (session cookie forgery) and **VULN-02** to **Critical** (unauthenticated database compromise).

---

## Detailed Vulnerability Findings

### VULN-01: Hardcoded Cryptographic Secret Key

* **Severity:** High
* **Vulnerable Location:** `vulnerable_app.py`, **Line 7**
* **Bandit Rule:** `B105: hardcoded_password_string`
* **CWE Mapping:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) / [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
* **OWASP Top 10 (2021):** `A02:2021 – Cryptographic Failures`

#### Vulnerable Code
```python
app.secret_key = "hardcoded_super_secret_key"  # Flaw 1: Hardcoded secret
```

#### Technical Analysis
Flask uses `app.secret_key` to cryptographically sign client-side session cookies and CSRF tokens. Hardcoding this key directly in source code exposes it to anyone with access to the codebase, version control history, or container image.

#### Proof-of-Concept (PoC) Exploit
An attacker who obtains `"hardcoded_super_secret_key"` from the repository can forge arbitrary signed session cookies offline using `flask-unsign`:
```bash
flask-unsign --sign --cookie "{'user': 'admin', 'role': 'superuser'}" --secret 'hardcoded_super_secret_key'
```
Sending the resulting cookie in an HTTP `Cookie: session=<forged_token>` header bypasses authentication checks.

#### Remediation
Load `FLASK_SECRET_KEY` dynamically from the runtime environment via `os.environ.get("FLASK_SECRET_KEY")` and fail fast at startup if the variable is missing or empty.

---

### VULN-02: SQL Injection via Unsanitized F-String Interpolation

* **Severity:** Critical
* **Vulnerable Location:** `vulnerable_app.py`, **Lines 15–16**
* **Bandit Rule:** `B608: hardcoded_sql_expressions`
* **CWE Mapping:** [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* **OWASP Top 10 (2021):** `A03:2021 – Injection`

#### Vulnerable Code
```python
query = f"SELECT id, username FROM users WHERE username = '{username}'"
result = conn.execute(query).fetchall()
```

#### Technical Analysis
User-controlled input from the `username` query parameter is concatenated directly into a raw SQL statement without parameterization or escaping. In addition, the SQLite connection is never explicitly closed, risking resource exhaustion.

#### Proof-of-Concept (PoC) Exploit Payloads
1. **Dump all users in the table (Boolean tautology):**
   ```http
   GET /user?username=' OR '1'='1 HTTP/1.1
   Host: 127.0.0.1:5000
   ```
   Resulting query executed by SQLite:
   ```sql
   SELECT id, username FROM users WHERE username = '' OR '1'='1'
   ```
2. **Extract database schema metadata (`UNION` injection):**
   ```http
   GET /user?username=' UNION SELECT sql, tbl_name FROM sqlite_master-- HTTP/1.1
   Host: 127.0.0.1:5000
   ```

#### Remediation
Use parameterized queries (`?` placeholders in `sqlite3`) so user input is bound strictly as literal data, and manage database connections with a `with` context manager.

---

### VULN-03: OS Command Injection via `shell=True`

* **Severity:** Critical
* **Vulnerable Location:** `vulnerable_app.py`, **Line 24**
* **Bandit Rule:** `B602: subprocess_popen_with_shell_equals_true`
* **CWE Mapping:** [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* **OWASP Top 10 (2021):** `A03:2021 – Injection`

#### Vulnerable Code
```python
output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
```

#### Technical Analysis
The `host` query parameter is interpolated into a command string executed inside `/bin/sh` (`shell=True`). Shell metacharacters (`;`, `&&`, `|`, `` ` ``, `$()`) allow an attacker to terminate the `ping` utility and execute arbitrary operating system commands with the privileges of the Flask process.

#### Proof-of-Concept (PoC) Exploit Payloads
1. **Execute `id` and read `/etc/passwd`:**
   ```http
   GET /ping?host=127.0.0.1%3Bid%3Bcat%20/etc/passwd HTTP/1.1
   Host: 127.0.0.1:5000
   ```
   Decoded command passed to `/bin/sh`:
   ```bash
   ping -c 1 127.0.0.1;id;cat /etc/passwd
   ```

#### Remediation
1. Validate `host` against a strict allowlist: parse valid IPv4/IPv6 addresses with Python's `ipaddress.ip_address()` or match valid RFC-1123 hostnames via strict regex (explicitly rejecting leading hyphens `-` to prevent `ping` flag injection).
2. Pass arguments as an explicit list (`["ping", "-c", "1", host]`) with `shell=False` so the OS invokes `ping` directly via `execve` without invoking a shell interpreter.

---

### VULN-04: Active Flask Debug Mode in Production Entrypoint

* **Severity:** High
* **Vulnerable Location:** `vulnerable_app.py`, **Line 29**
* **Bandit Rule:** `B201: flask_debug_true`
* **CWE Mapping:** [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html) / [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
* **OWASP Top 10 (2021):** `A05:2021 – Security Misconfiguration`

#### Vulnerable Code
```python
if __name__ == "__main__":
    app.run(debug=True)  # Flaw 4: Debug mode enabled in production
```

#### Technical Analysis
Running Flask with `debug=True` enables automatic code reloading and the interactive Werkzeug debugger on unhandled exceptions. Any runtime exception discloses full stack traces, source code snippets, and local variable states, and exposes an interactive Python console (`/console`) capable of Remote Code Execution (RCE) if the debugger PIN is compromised or disabled.

#### Proof-of-Concept (PoC) Exploit
Triggering a non-zero exit code in `/ping` (e.g., `GET /ping?host=256.256.256.256`) raises `subprocess.CalledProcessError`, rendering the interactive Werkzeug traceback page directly to the remote client.

#### Remediation
Set `debug=False` explicitly in `app.run()`, handle exceptions gracefully with generic JSON/HTTP error responses, and deploy behind a production WSGI server (such as Gunicorn) in live environments.

---

## Verification of Remediation (`secure_app.py`)

After implementing all fixes in `secure_app.py`, re-running `bandit -r secure_app.py` confirms **0 High** and **0 Medium** severity alerts.
