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

if not ANTHROPIC_KEY:
    raise RuntimeError("ANTHROPIC_KEY environment variable is not set")
if not ADVISOR_USER or not ADVISOR_PASS:
    raise RuntimeError("ADVISOR_USER and ADVISOR_PASS environment variables must be set")

# ---- DATABASE ----
def get_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Sessions (DB-backed)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            username   TEXT NOT NULL,
            role       TEXT NOT NULL,
            family_id  TEXT,
            member_id  TEXT,
            expires    TEXT NOT NULL
        )
    """)

    # Families
    c.execute("""
        CREATE TABLE IF NOT EXISTS families (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    # Family members — each has their own login
    c.execute("""
        CREATE TABLE IF NOT EXISTS family_members (
            id            TEXT PRIMARY KEY,
            family_id     TEXT NOT NULL,
            name          TEXT NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            phone         TEXT,
            role          TEXT DEFAULT 'member',
            password_hash TEXT NOT NULL,
            created_at    TEXT,
            updated_at    TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id)
        )
    """)

    # Per-member data: income_expenses, assets_liabilities, insurance, risk_profile
    c.execute("""
        CREATE TABLE IF NOT EXISTS member_data (
            id         TEXT PRIMARY KEY,
            family_id  TEXT NOT NULL,
            member_id  TEXT NOT NULL,
            section    TEXT NOT NULL,
            data       TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id),
            FOREIGN KEY (member_id) REFERENCES family_members(id),
            UNIQUE(member_id, section)
        )
    """)

    # Family-level data: goals
    c.execute("""
        CREATE TABLE IF NOT EXISTS family_data (
            id         TEXT PRIMARY KEY,
            family_id  TEXT NOT NULL,
            section    TEXT NOT NULL,
            data       TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id),
            UNIQUE(family_id, section)
        )
    """)

    # Financial plans — one per family
    c.execute("""
        CREATE TABLE IF NOT EXISTS financial_plans (
            id         TEXT PRIMARY KEY,
            family_id  TEXT NOT NULL,
            plan       TEXT NOT NULL,
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id)
        )
    """)

    # Legacy tables (keep for backward compat)
    c.execute("""CREATE TABLE IF NOT EXISTS clients_test (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        phone TEXT, password_hash TEXT NOT NULL, created_at TEXT, updated_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS financial_data_test (
        id TEXT PRIMARY KEY, client_id TEXT NOT NULL, section TEXT NOT NULL,
        data TEXT NOT NULL, updated_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS financial_plans_test (
        id TEXT PRIMARY KEY, client_id TEXT NOT NULL, plan TEXT NOT NULL,
        created_at TEXT, updated_at TEXT)""")

    conn.commit()
    conn.close()
    print("Database initialized")

init_db()

# ---- AUTH HELPERS ----
def create_session(username, role, family_id=None, member_id=None):
    token   = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    conn    = get_db()
    conn.execute(
        "INSERT INTO sessions (token, username, role, family_id, member_id, expires) VALUES (?,?,?,?,?,?)",
        (token, username, role, family_id, member_id, expires)
    )
    conn.commit()
    conn.close()
    return token

def get_session():
    token = request.headers.get("X-Auth-Token")
    if not token:
        return None
    conn = get_db()
    try:
        session = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
        if not session:
            return None
        if datetime.now() > datetime.strptime(session["expires"], "%Y-%m-%d %H:%M:%S"):
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return None
        return dict(session)
    finally:
        conn.close()

def require_auth(role=None):
    session = get_session()
    if not session:
        return jsonify({"error": "Please login"}), 401
    if role and session["role"] != role and session["role"] != "advisor":
        return jsonify({"error": "Insufficient permissions"}), 403
    return None

# ================================================================
#  AUTH
# ================================================================
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if username == ADVISOR_USER.lower() and password == ADVISOR_PASS:
        token = create_session(username, "advisor")
        return jsonify({"status":"success","token":token,"role":"advisor","name":"Advisor","username":username})

    conn   = get_db()
    member = conn.execute("SELECT * FROM family_members WHERE LOWER(email)=?", (username,)).fetchone()
    conn.close()

    if member and check_password_hash(member["password_hash"], password):
        token = create_session(member["email"], "client",
                               family_id=member["family_id"], member_id=member["id"])
        return jsonify({
            "status":"success","token":token,"role":"client",
            "name":member["name"],"username":member["email"],
            "family_id":member["family_id"],"member_id":member["id"]
        })

    return jsonify({"error": "Invalid username or password"}), 401

@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.headers.get("X-Auth-Token")
    if token:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    return jsonify({"status": "success"})

# ================================================================
#  FAMILY MANAGEMENT  (Advisor only)
# ================================================================
@app.route("/api/families", methods=["GET"])
def get_families():
    auth = require_auth("advisor")
    if auth: return auth

    conn     = get_db()
    families = conn.execute("SELECT * FROM families ORDER BY name").fetchall()
    result   = []
    for f in families:
        members = conn.execute(
            "SELECT id,name,email,phone,role FROM family_members WHERE family_id=? ORDER BY role DESC",
            (f["id"],)
        ).fetchall()
        plan = conn.execute(
            "SELECT updated_at FROM financial_plans WHERE family_id=? ORDER BY created_at DESC LIMIT 1",
            (f["id"],)
        ).fetchone()
        result.append({**dict(f), "members":[dict(m) for m in members],
                       "member_count":len(members), "has_plan":plan is not None,
                       "plan_date":plan["updated_at"] if plan else None})
    conn.close()
    return jsonify(result)

@app.route("/api/families", methods=["POST"])
def create_family():
    auth = require_auth("advisor")
    if auth: return auth

    data        = request.json
    family_name = data.get("name","").strip()
    members     = data.get("members",[])

    if not family_name:
        return jsonify({"error":"Family name is required"}), 400
    if not members:
        return jsonify({"error":"At least one member is required"}), 400

    family_id = str(uuid.uuid4())
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn      = get_db()
    try:
        conn.execute("INSERT INTO families (id,name,created_at,updated_at) VALUES (?,?,?,?)",
                     (family_id, family_name, now, now))
        for m in members:
            conn.execute(
                "INSERT INTO family_members (id,family_id,name,email,phone,role,password_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), family_id,
                 m.get("name","").strip(), m.get("email","").strip().lower(),
                 m.get("phone","").strip(), m.get("role","member"),
                 generate_password_hash(m.get("password","")), now, now)
            )
        conn.commit()
        return jsonify({"status":"success","family_id":family_id,"message":f"{family_name} created!"})
    except sqlite3.IntegrityError as e:
        conn.rollback()
        return jsonify({"error":f"Email already exists: {str(e)}"}), 400
    finally:
        conn.close()

@app.route("/api/families/<family_id>", methods=["GET"])
def get_family(family_id):
    auth = require_auth()
    if auth: return auth
    session = get_session()
    if session["role"] == "client" and session.get("family_id") != family_id:
        return jsonify({"error":"Access denied"}), 403

    conn   = get_db()
    family = conn.execute("SELECT * FROM families WHERE id=?", (family_id,)).fetchone()
    if not family:
        conn.close()
        return jsonify({"error":"Family not found"}), 404
    members = conn.execute(
        "SELECT id,name,email,phone,role FROM family_members WHERE family_id=? ORDER BY role DESC",
        (family_id,)
    ).fetchall()
    conn.close()
    return jsonify({**dict(family), "members":[dict(m) for m in members]})

@app.route("/api/families/<family_id>", methods=["DELETE"])
def delete_family(family_id):
    auth = require_auth("advisor")
    if auth: return auth
    conn = get_db()
    for tbl in ["financial_plans","family_data","member_data","family_members","families"]:
        col = "family_id" if tbl != "families" else "id"
        conn.execute(f"DELETE FROM {tbl} WHERE {col}=?", (family_id,))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

@app.route("/api/families/<family_id>/members", methods=["POST"])
def add_member(family_id):
    auth = require_auth("advisor")
    if auth: return auth
    data = request.json
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mid  = str(uuid.uuid4())
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO family_members (id,family_id,name,email,phone,role,password_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (mid, family_id, data.get("name","").strip(), data.get("email","").strip().lower(),
             data.get("phone","").strip(), data.get("role","member"),
             generate_password_hash(data.get("password","")), now, now)
        )
        conn.commit()
        return jsonify({"status":"success","member_id":mid})
    except sqlite3.IntegrityError:
        return jsonify({"error":"Email already exists"}), 400
    finally:
        conn.close()

@app.route("/api/families/<family_id>/members/<member_id>", methods=["DELETE"])
def delete_member(family_id, member_id):
    auth = require_auth("advisor")
    if auth: return auth
    conn = get_db()
    conn.execute("DELETE FROM member_data WHERE member_id=?", (member_id,))
    conn.execute("DELETE FROM family_members WHERE id=? AND family_id=?", (member_id, family_id))
    conn.commit()
    conn.close()
    return jsonify({"status":"success"})

# ================================================================
#  FINANCIAL DATA
# ================================================================
MEMBER_SECTIONS = ["income_expenses","assets_liabilities","insurance","risk_profile"]
FAMILY_SECTIONS = ["goals"]

@app.route("/api/families/<family_id>/data", methods=["GET"])
def get_family_data(family_id):
    auth = require_auth()
    if auth: return auth
    session = get_session()
    if session["role"] == "client" and session.get("family_id") != family_id:
        return jsonify({"error":"Access denied"}), 403

    conn        = get_db()
    member_rows = conn.execute(
        """SELECT md.member_id, md.section, md.data, fm.name as member_name
           FROM member_data md JOIN family_members fm ON md.member_id=fm.id
           WHERE md.family_id=?""", (family_id,)
    ).fetchall()
    family_rows = conn.execute(
        "SELECT section,data FROM family_data WHERE family_id=?", (family_id,)
    ).fetchall()
    members = conn.execute(
        "SELECT id,name,email,role FROM family_members WHERE family_id=? ORDER BY role DESC",
        (family_id,)
    ).fetchall()
    conn.close()

    member_data = {}
    for row in member_rows:
        mid = row["member_id"]
        if mid not in member_data:
            member_data[mid] = {"name": row["member_name"]}
        member_data[mid][row["section"]] = json.loads(row["data"])

    return jsonify({
        "members"    : [dict(m) for m in members],
        "member_data": member_data,
        "family_data": {r["section"]: json.loads(r["data"]) for r in family_rows}
    })

@app.route("/api/families/<family_id>/members/<member_id>/data/<section>", methods=["POST"])
def save_member_data(family_id, member_id, section):
    auth = require_auth("advisor")
    if auth: return auth
    if section not in MEMBER_SECTIONS:
        return jsonify({"error":f"Invalid section. Use: {MEMBER_SECTIONS}"}), 400

    data = request.json
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM member_data WHERE member_id=? AND section=?", (member_id, section)
    ).fetchone()
    if existing:
        conn.execute("UPDATE member_data SET data=?,updated_at=? WHERE member_id=? AND section=?",
                     (json.dumps(data), now, member_id, section))
    else:
        conn.execute("INSERT INTO member_data (id,family_id,member_id,section,data,updated_at) VALUES (?,?,?,?,?,?)",
                     (str(uuid.uuid4()), family_id, member_id, section, json.dumps(data), now))
    conn.commit()
    conn.close()
    return jsonify({"status":"success","message":f"{section} saved!"})

@app.route("/api/families/<family_id>/data/<section>", methods=["POST"])
def save_family_level_data(family_id, section):
    auth = require_auth("advisor")
    if auth: return auth
    if section not in FAMILY_SECTIONS:
        return jsonify({"error":f"Invalid section. Use: {FAMILY_SECTIONS}"}), 400

    data = request.json
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM family_data WHERE family_id=? AND section=?", (family_id, section)
    ).fetchone()
    if existing:
        conn.execute("UPDATE family_data SET data=?,updated_at=? WHERE family_id=? AND section=?",
                     (json.dumps(data), now, family_id, section))
    else:
        conn.execute("INSERT INTO family_data (id,family_id,section,data,updated_at) VALUES (?,?,?,?,?)",
                     (str(uuid.uuid4()), family_id, section, json.dumps(data), now))
    conn.commit()
    conn.close()
    return jsonify({"status":"success","message":f"{section} saved!"})

# ================================================================
#  FINANCIAL PLAN
# ================================================================
@app.route("/api/families/<family_id>/plan", methods=["GET"])
def get_family_plan(family_id):
    auth = require_auth()
    if auth: return auth
    session = get_session()
    if session["role"] == "client" and session.get("family_id") != family_id:
        return jsonify({"error":"Access denied"}), 403

    conn = get_db()
    plan = conn.execute(
        "SELECT * FROM financial_plans WHERE family_id=? ORDER BY created_at DESC LIMIT 1",
        (family_id,)
    ).fetchone()
    conn.close()
    if plan:
        return jsonify({"plan":plan["plan"],"updated_at":plan["updated_at"]})
    return jsonify({"plan":None})

@app.route("/api/families/<family_id>/plan/generate", methods=["POST"])
def generate_family_plan(family_id):
    auth = require_auth("advisor")
    if auth: return auth

    conn   = get_db()
    family = conn.execute("SELECT * FROM families WHERE id=?", (family_id,)).fetchone()
    if not family:
        conn.close()
        return jsonify({"error":"Family not found"}), 404

    members     = conn.execute("SELECT id,name,role FROM family_members WHERE family_id=?", (family_id,)).fetchall()
    member_data = {}
    for m in members:
        rows = conn.execute("SELECT section,data FROM member_data WHERE member_id=?", (m["id"],)).fetchall()
        member_data[m["name"]] = {r["section"]: json.loads(r["data"]) for r in rows}
    family_rows  = conn.execute("SELECT section,data FROM family_data WHERE family_id=?", (family_id,)).fetchall()
    family_level = {r["section"]: json.loads(r["data"]) for r in family_rows}
    conn.close()

    # Compute combined numbers
    total_income = total_expenses = total_assets = total_liabilities = 0
    for name, data in member_data.items():
        ie = data.get("income_expenses", {})
        al = data.get("assets_liabilities", {})
        total_income      += sum(ie.get(k,0) for k in ["primary_income","secondary_income","rental_income","other_income"])
        total_expenses    += sum(ie.get(k,0) for k in ["emi","rent","sip","savings","household","transport","lifestyle","insurance_premium","other_expenses"])
        total_assets      += sum(al.get(k,0) for k in ["real_estate","gold","equity","debt_instruments","epf_ppf","cash","vehicles","other_assets"])
        total_liabilities += sum(al.get(k,0) for k in ["home_loan","car_loan","personal_loan","credit_card","other_loans"])

    try:
        ai_client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        prompt = f"""You are an expert SEBI-registered financial planner in India.
Create a comprehensive family financial plan for the {family["name"]} family.

FAMILY OVERVIEW:
- Members: {', '.join(m['name'] for m in members)}
- Combined monthly income: ₹{total_income:,.0f}
- Combined monthly expenses: ₹{total_expenses:,.0f}
- Monthly surplus: ₹{total_income - total_expenses:,.0f}
- Total family assets: ₹{total_assets:,.0f}
- Total liabilities: ₹{total_liabilities:,.0f}
- Family net worth: ₹{total_assets - total_liabilities:,.0f}

DETAILED DATA:
{json.dumps({"members": member_data, "shared_goals": family_level.get("goals", {})}, indent=2)}

Create a plan with sections:
1. EXECUTIVE SUMMARY (health score /10, strengths, concerns)
2. INCOME & CASH FLOW (combined breakdown, savings rate, optimisation)
3. EMERGENCY FUND (recommended amount, current status, how to build)
4. INSURANCE REVIEW (term cover per member, health floater, gap analysis)
5. DEBT MANAGEMENT (loans, EMI burden, prepayment strategy)
6. INVESTMENT PLAN (asset allocation, SIP breakdown per member, lumpsum)
7. GOALS PLANNING (corpus needed, SIP required, instruments per goal)
8. TAX PLANNING (80C per member, HRA, NPS, total savings)
9. ACTION PLAN (immediate / 3-6 months / 1 year+)

Use ₹ for amounts. Be specific with numbers. Address both members by name."""

        response = ai_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            messages=[{"role":"user","content":prompt}]
        )
    except anthropic.APIError as e:
        return jsonify({"error":f"AI generation failed: {str(e)}"}), 500

    plan_text = response.content[0].text
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn      = get_db()
    existing  = conn.execute("SELECT id FROM financial_plans WHERE family_id=?", (family_id,)).fetchone()
    if existing:
        conn.execute("UPDATE financial_plans SET plan=?,updated_at=? WHERE family_id=?",
                     (plan_text, now, family_id))
    else:
        conn.execute("INSERT INTO financial_plans (id,family_id,plan,created_at,updated_at) VALUES (?,?,?,?,?)",
                     (str(uuid.uuid4()), family_id, plan_text, now, now))
    conn.commit()
    conn.close()
    return jsonify({"status":"success","plan":plan_text,"updated_at":now})

# ================================================================
#  DEBUG + STATIC
# ================================================================
@app.route("/api/debug")
def debug():
    return jsonify({"status":"running","db_path":DB_PATH,
                    "timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

@app.route("/")
def serve_index():
    if os.path.exists("index.html"):
        return send_from_directory(".", "index.html")
    return jsonify({"status":"Fleek Finance API running"})

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("FLASK_DEBUG","false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
