from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import anthropic
import sqlite3
import json
import os
import uuid
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
CORS(app)

@app.after_request
def allow_iframe(response):
    response.headers.pop("X-Frame-Options", None)
    response.headers["Content-Security-Policy"] = "frame-ancestors 'self' https://fleekfinance.in"
    return response

# ---- CONFIG ----
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_KEY")
ADVISOR_USER  = os.environ.get("ADVISOR_USER")
ADVISOR_PASS  = os.environ.get("ADVISOR_PASS")
DB_PATH       = os.environ.get("DB_PATH", "financial_planner.db")

# Fail fast if required env vars are missing
if not ANTHROPIC_KEY:
    raise RuntimeError("ANTHROPIC_KEY environment variable is not set")
if not ADVISOR_USER or not ADVISOR_PASS:
    raise RuntimeError("ADVISOR_USER and ADVISOR_PASS environment variables must be set")

# In-memory session store
# NOTE: This will not persist across Gunicorn workers or restarts.
# For production with multiple workers, replace with Redis or a DB-backed store.
sessions = {}  # {token: {username, role, expires}}


# ---- DATABASE SETUP ----
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c    = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS clients_test (
            id            TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            phone         TEXT,
            password_hash TEXT NOT NULL,
            created_at    TEXT,
            updated_at    TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS financial_data_test (
            id         TEXT PRIMARY KEY,
            client_id  TEXT NOT NULL,
            section    TEXT NOT NULL,
            data       TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (client_id) REFERENCES clients_test(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS financial_plans_test (
            id         TEXT PRIMARY KEY,
            client_id  TEXT NOT NULL,
            plan       TEXT NOT NULL,
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY (client_id) REFERENCES clients_test(id)
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized")


init_db()


# ---- AUTH HELPERS ----
def create_session(username, role):
    token   = secrets.token_hex(32)
    expires = datetime.now() + timedelta(hours=8)
    sessions[token] = {
        "username": username,
        "role"    : role,
        "expires" : expires
    }
    return token


def get_session():
    token = request.headers.get("X-Auth-Token")
    if not token or token not in sessions:
        return None
    session = sessions[token]
    if datetime.now() > session["expires"]:
        del sessions[token]
        return None
    return session


def require_auth(role=None):
    session = get_session()
    if not session:
        return jsonify({"error": "Please login"}), 401
    if role and session["role"] != role and session["role"] != "advisor":
        return jsonify({"error": "Insufficient permissions"}), 403
    return None


# ---- AUTH ROUTES ----
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    # Check advisor login
    if username == ADVISOR_USER.lower() and password == ADVISOR_PASS:
        token = create_session(username, "advisor")
        return jsonify({
            "status"  : "success",
            "token"   : token,
            "role"    : "advisor",
            "name"    : "Advisor",
            "username": username
        })

    # Check client login (by email)
    conn   = get_db()
    client = conn.execute(
        "SELECT * FROM clients_test WHERE LOWER(email) = ?", (username,)
    ).fetchone()
    conn.close()

    if client and check_password_hash(client["password_hash"], password):
        token = create_session(client["email"], "client")
        return jsonify({
            "status"   : "success",
            "token"    : token,
            "role"     : "client",
            "name"     : client["name"],
            "username" : client["email"],
            "client_id": client["id"]
        })

    return jsonify({"error": "Invalid username or password"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.headers.get("X-Auth-Token")
    if token in sessions:
        del sessions[token]
    return jsonify({"status": "success"})


# ---- CLIENT MANAGEMENT (Advisor only) ----
@app.route("/api/clients", methods=["GET"])
def get_clients():
    auth = require_auth("advisor")
    if auth: return auth

    conn    = get_db()
    clients = conn.execute(
        "SELECT id, name, email, phone, created_at FROM clients_test ORDER BY name"
    ).fetchall()
    conn.close()

    return jsonify([dict(c) for c in clients])


@app.route("/api/clients", methods=["POST"])
def add_client():
    auth = require_auth("advisor")
    if auth: return auth

    data  = request.json
    name  = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    phone = data.get("phone", "").strip()
    pwd   = data.get("password", "")

    if not name or not email or not pwd:
        return jsonify({"error": "Name, email and password are required"}), 400

    client_id = str(uuid.uuid4())
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO clients_test (id, name, email, phone, password_hash, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (client_id, name, email, phone, generate_password_hash(pwd), now, now)
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "client_id": client_id, "message": f"{name} added!"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 400


@app.route("/api/clients/<client_id>", methods=["DELETE"])
def delete_client(client_id):
    auth = require_auth("advisor")
    if auth: return auth

    conn = get_db()
    conn.execute("DELETE FROM clients_test WHERE id = ?", (client_id,))
    conn.execute("DELETE FROM financial_data_test WHERE client_id = ?", (client_id,))
    conn.execute("DELETE FROM financial_plans_test WHERE client_id = ?", (client_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


# ---- FINANCIAL DATA ----
SECTIONS = [
    "income_expenses",
    "assets_liabilities",
    "insurance",
    "investments",
    "goals",
    "risk_profile"
]


@app.route("/api/clients/<client_id>/data", methods=["GET"])
def get_financial_data(client_id):
    auth = require_auth()
    if auth: return auth

    conn = get_db()

    # Clients can only view their own data
    session = get_session()
    if session["role"] == "client":
        client_row = conn.execute(
            "SELECT id FROM clients_test WHERE email = ?", (session["username"],)
        ).fetchone()
        if not client_row or client_row["id"] != client_id:
            conn.close()
            return jsonify({"error": "Access denied"}), 403

    rows   = conn.execute(
        "SELECT section, data FROM financial_data_test WHERE client_id = ?", (client_id,)
    ).fetchall()
    client = conn.execute(
        "SELECT name, email, phone FROM clients_test WHERE id = ?", (client_id,)
    ).fetchone()
    conn.close()

    result = {"client": dict(client) if client else {}}
    for row in rows:
        result[row["section"]] = json.loads(row["data"])

    return jsonify(result)


@app.route("/api/clients/<client_id>/data/<section>", methods=["POST"])
def save_financial_data(client_id, section):
    auth = require_auth("advisor")
    if auth: return auth

    if section not in SECTIONS:
        return jsonify({"error": f"Invalid section. Use: {SECTIONS}"}), 400

    data = request.json
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn     = get_db()
    existing = conn.execute(
        "SELECT id FROM financial_data_test WHERE client_id = ? AND section = ?",
        (client_id, section)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE financial_data_test SET data = ?, updated_at = ? WHERE client_id = ? AND section = ?",
            (json.dumps(data), now, client_id, section)
        )
    else:
        conn.execute(
            "INSERT INTO financial_data_test (id, client_id, section, data, updated_at) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), client_id, section, json.dumps(data), now)
        )

    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"{section} saved!"})


# ---- FINANCIAL PLAN ----
@app.route("/api/clients/<client_id>/plan", methods=["GET"])
def get_plan(client_id):
    auth = require_auth()
    if auth: return auth

    conn = get_db()

    session = get_session()
    if session["role"] == "client":
        client_row = conn.execute(
            "SELECT id FROM clients_test WHERE email = ?", (session["username"],)
        ).fetchone()
        if not client_row or client_row["id"] != client_id:
            conn.close()
            return jsonify({"error": "Access denied"}), 403

    plan = conn.execute(
        "SELECT * FROM financial_plans_test WHERE client_id = ? ORDER BY created_at DESC LIMIT 1",
        (client_id,)
    ).fetchone()
    conn.close()

    if plan:
        return jsonify({"plan": plan["plan"], "updated_at": plan["updated_at"]})
    return jsonify({"plan": None})


@app.route("/api/clients/<client_id>/plan/generate", methods=["POST"])
def generate_plan(client_id):
    auth = require_auth("advisor")
    if auth: return auth

    conn   = get_db()
    rows   = conn.execute(
        "SELECT section, data FROM financial_data_test WHERE client_id = ?", (client_id,)
    ).fetchall()
    client = conn.execute(
        "SELECT name FROM clients_test WHERE id = ?", (client_id,)
    ).fetchone()
    conn.close()

    if not client:
        return jsonify({"error": "Client not found"}), 404

    financial_data = {row["section"]: json.loads(row["data"]) for row in rows}

    # Generate plan with Claude
    try:
        ai_client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        prompt    = f"""
You are an expert SEBI registered financial planner in India.
Create a comprehensive financial plan for {client["name"]}.

CLIENT FINANCIAL DATA:
{json.dumps(financial_data, indent=2)}

Create a detailed financial plan with these sections:

1. EXECUTIVE SUMMARY
   - Current financial health score (out of 10)
   - Key strengths and concerns

2. INCOME & EXPENSE ANALYSIS
   - Monthly surplus/deficit
   - Savings rate assessment
   - Expense optimization suggestions

3. EMERGENCY FUND
   - Current status
   - Recommended amount
   - How to build it

4. INSURANCE RECOMMENDATIONS
   - Life insurance (term plan) — cover amount & premium estimate
   - Health insurance — cover amount
   - Critical illness / accidental cover if needed
   - Gap analysis vs existing coverage

5. DEBT MANAGEMENT
   - Priority order to repay loans
   - EMI to income ratio assessment

6. INVESTMENT PLAN
   - Asset allocation (equity/debt/gold) based on risk profile
   - Specific mutual fund categories to invest in
   - Monthly SIP recommendation with amounts
   - Lumpsum deployment if applicable

7. GOALS PLANNING
   - For each goal: required corpus, monthly investment needed, recommended instruments

8. TAX PLANNING
   - 80C optimization
   - Other deductions applicable
   - Estimated tax savings

9. ACTION PLAN
   - Immediate actions (this month)
   - Short term (3-6 months)
   - Long term (1 year+)

Use ₹ for all amounts. Be specific with numbers.
"""

        response = ai_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )
    except anthropic.APIError as e:
        return jsonify({"error": f"AI generation failed: {str(e)}"}), 500

    plan_text = response.content[0].text
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # FIX: Save to financial_plans_test (not financial_data_test)
    conn     = get_db()
    existing = conn.execute(
        "SELECT id FROM financial_plans_test WHERE client_id = ?", (client_id,)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE financial_plans_test SET plan = ?, updated_at = ? WHERE client_id = ?",
            (plan_text, now, client_id)
        )
    else:
        conn.execute(
            "INSERT INTO financial_plans_test (id, client_id, plan, created_at, updated_at) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), client_id, plan_text, now, now)
        )

    conn.commit()
    conn.close()
    return jsonify({"status": "success", "plan": plan_text, "updated_at": now})


# ---- STATIC FRONTEND ----
@app.route("/")
def serve_index():
    return send_from_directory(".", "index.html")


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
