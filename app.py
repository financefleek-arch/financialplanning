from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import anthropic
import sqlite3
import json
import os
import uuid
import base64
import tempfile
from datetime import datetime, timedelta
import secrets

# casparser — handles both CAMS and KFintech CAS PDFs
try:
    import casparser
    CASPARSER_AVAILABLE = True
except ImportError:
    CASPARSER_AVAILABLE = False

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

# Rate limiter — tracks FAILED attempts per IP, not all attempts
# Blocks after 10 failed attempts per minute (brute force protection)
from collections import defaultdict
_failed_attempts = defaultdict(list)

def check_rate_limit(ip):
    """Returns True if request is allowed, False if rate limited."""
    now    = datetime.now()
    cutoff = now - timedelta(minutes=1)
    _failed_attempts[ip] = [t for t in _failed_attempts[ip] if t > cutoff]
    return len(_failed_attempts[ip]) < 10

def record_failed_login(ip):
    _failed_attempts[ip].append(datetime.now())

# ---- DATABASE ----
def get_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)  # wait up to 15s on lock
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")    # concurrent reads, safe writes
    conn.execute("PRAGMA synchronous = NORMAL")  # faster writes, still crash-safe
    conn.execute("PRAGMA cache_size = -4000")    # 4MB page cache
    conn.execute("PRAGMA busy_timeout = 10000")  # 10s busy timeout at SQLite level
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
    # Index for fast session lookups and cleanup
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token   ON sessions(token)")

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
            id                   TEXT PRIMARY KEY,
            family_id            TEXT NOT NULL,
            name                 TEXT NOT NULL,
            email                TEXT UNIQUE NOT NULL,
            phone                TEXT,
            role                 TEXT DEFAULT 'member',
            password_hash        TEXT NOT NULL,
            allow_password_change INTEGER DEFAULT 1,
            created_at           TEXT,
            updated_at           TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id)
        )
    """)

    # Migration: add allow_password_change to existing DBs
    try:
        c.execute("ALTER TABLE family_members ADD COLUMN allow_password_change INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass  # column already exists

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
            plan       TEXT,
            pdf_data   TEXT,
            plan_type  TEXT DEFAULT 'text',
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id)
        )
    """)

    # Migration: add pdf_data and plan_type columns if they don't exist
    try:
        c.execute("ALTER TABLE financial_plans ADD COLUMN pdf_data TEXT")
        c.execute("ALTER TABLE financial_plans ADD COLUMN plan_type TEXT DEFAULT 'text'")
    except sqlite3.OperationalError:
        pass  # columns already exist

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

    # CAS portfolios — parsed mutual fund data per member
    c.execute("""
        CREATE TABLE IF NOT EXISTS cas_portfolios (
            id          TEXT PRIMARY KEY,
            family_id   TEXT NOT NULL,
            member_id   TEXT NOT NULL,
            cas_type    TEXT,
            parsed_data TEXT NOT NULL,
            uploaded_at TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id),
            FOREIGN KEY (member_id) REFERENCES family_members(id),
            UNIQUE(member_id)
        )
    """)

    conn.commit()
    conn.close()
    print("Database initialized")

init_db()

# ---- AUTH HELPERS ----
def create_session(username, role, family_id=None, member_id=None):
    token   = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    conn    = get_db()
    # Clean up expired sessions on every login — keeps the table small
    conn.execute("DELETE FROM sessions WHERE expires < ?",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
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
    try:
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
    except sqlite3.OperationalError:
        return None  # DB temporarily locked — treat as unauthenticated

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
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not check_rate_limit(ip):
        return jsonify({"error": "Too many failed login attempts. Please wait a minute."}), 429

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
            "family_id":member["family_id"],"member_id":member["id"],
            "allow_password_change": bool(member["allow_password_change"])
        })

    # Only count failed attempts toward rate limit
    record_failed_login(ip)
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
            allow_pw = 0 if not m.get("allow_password_change", True) else 1
            conn.execute(
                "INSERT INTO family_members (id,family_id,name,email,phone,role,password_hash,allow_password_change,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), family_id,
                 m.get("name","").strip(), m.get("email","").strip().lower(),
                 m.get("phone","").strip(), m.get("role","member"),
                 generate_password_hash(m.get("password","")),
                 allow_pw, now, now)
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
        "SELECT id,name,email,phone,role,allow_password_change FROM family_members WHERE family_id=? ORDER BY role DESC",
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
        allow_pw = 0 if not data.get("allow_password_change", True) else 1
        conn.execute(
            "INSERT INTO family_members (id,family_id,name,email,phone,role,password_hash,allow_password_change,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (mid, family_id, data.get("name","").strip(), data.get("email","").strip().lower(),
             data.get("phone","").strip(), data.get("role","member"),
             generate_password_hash(data.get("password","")), allow_pw, now, now)
        )
        conn.commit()
        return jsonify({"status":"success","member_id":mid})
    except sqlite3.IntegrityError:
        return jsonify({"error":"Email already exists"}), 400
    finally:
        conn.close()

@app.route("/api/families/<family_id>/members/<member_id>", methods=["PUT"])
def edit_member(family_id, member_id):
    """Advisor: edit member profile (name, email, phone, role, optional password reset)."""
    auth = require_auth("advisor")
    if auth: return auth

    data = request.json
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()

    member = conn.execute(
        "SELECT * FROM family_members WHERE id=? AND family_id=?", (member_id, family_id)
    ).fetchone()
    if not member:
        conn.close()
        return jsonify({"error": "Member not found"}), 404

    name     = data.get("name",  member["name"]).strip()
    email    = data.get("email", member["email"]).strip().lower()
    phone    = data.get("phone", member["phone"] or "").strip()
    role     = data.get("role",  member["role"])
    allow_pw = 0 if not data.get("allow_password_change", True) else 1
    new_password = data.get("password", "").strip()

    try:
        if new_password:
            conn.execute(
                "UPDATE family_members SET name=?,email=?,phone=?,role=?,password_hash=?,allow_password_change=?,updated_at=? WHERE id=?",
                (name, email, phone, role, generate_password_hash(new_password), allow_pw, now, member_id)
            )
        else:
            conn.execute(
                "UPDATE family_members SET name=?,email=?,phone=?,role=?,allow_password_change=?,updated_at=? WHERE id=?",
                (name, email, phone, role, allow_pw, now, member_id)
            )
        conn.commit()
        return jsonify({"status": "success", "message": f"{name} updated!"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already in use by another member"}), 400
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

@app.route("/api/members/<member_id>/change-password", methods=["POST"])
def change_password(member_id):
    """Client: change their own password."""
    auth = require_auth()
    if auth: return auth

    session = get_session()
    # Clients can only change their own password
    if session["role"] == "client" and session.get("member_id") != member_id:
        return jsonify({"error": "Access denied"}), 403

    data         = request.json
    current_pass = data.get("current_password", "")
    new_pass     = data.get("new_password", "").strip()

    if not current_pass or not new_pass:
        return jsonify({"error": "Both current and new password are required"}), 400
    if len(new_pass) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    conn   = get_db()
    member = conn.execute("SELECT * FROM family_members WHERE id=?", (member_id,)).fetchone()
    if not member:
        conn.close()
        return jsonify({"error": "Member not found"}), 404

    if not check_password_hash(member["password_hash"], current_pass):
        conn.close()
        return jsonify({"error": "Current password is incorrect"}), 400

    if not member["allow_password_change"]:
        conn.close()
        return jsonify({"error": "Password changes are disabled for your account. Please contact your advisor."}), 403

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE family_members SET password_hash=?,updated_at=? WHERE id=?",
        (generate_password_hash(new_pass), now, member_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Password changed successfully!"})


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
        "SELECT id,name,email,role,allow_password_change FROM family_members WHERE family_id=? ORDER BY role DESC",
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
        return jsonify({
            "plan"      : plan["plan"],
            "pdf_data"  : plan["pdf_data"],
            "plan_type" : plan["plan_type"] or "text",
            "updated_at": plan["updated_at"]
        })
    return jsonify({"plan": None, "pdf_data": None})

@app.route("/api/families/<family_id>/plan/upload", methods=["POST"])
def upload_plan_pdf(family_id):
    """Upload a PDF plan manually (base64 encoded)."""
    auth = require_auth("advisor")
    if auth: return auth

    data     = request.json
    pdf_data = data.get("pdf_data", "")
    filename = data.get("filename", "plan.pdf")

    if not pdf_data or not pdf_data.startswith("data:application/pdf"):
        return jsonify({"error": "Invalid PDF data"}), 400

    # Rough size check — base64 of 10MB is ~13.3MB string
    if len(pdf_data) > 14_000_000:
        return jsonify({"error": "PDF too large. Maximum size is 10MB."}), 400

    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM financial_plans WHERE family_id=?", (family_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE financial_plans SET pdf_data=?, plan='', plan_type='pdf', updated_at=? WHERE family_id=?",
                (pdf_data, now, family_id)
            )
        else:
            conn.execute(
                "INSERT INTO financial_plans (id,family_id,plan,pdf_data,plan_type,created_at,updated_at) VALUES (?,?,?,?,'pdf',?,?)",
                (str(uuid.uuid4()), family_id, '', pdf_data, now, now)
            )
        conn.commit()
        return jsonify({"status": "success", "message": f"{filename} uploaded!", "updated_at": now})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500
    finally:
        conn.close()

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
#  XIRR — pure Python, no scipy needed
# ================================================================
def xirr(cashflows):
    """
    cashflows: list of (date_str_YYYY-MM-DD, amount)
    Positive = inflow (purchase), Negative = outflow (redemption/current value)
    Returns annualised XIRR as a float (e.g. 0.142 = 14.2%), or None if fails.
    """
    if len(cashflows) < 2:
        return None
    try:
        from datetime import date as dt
        dates   = [datetime.strptime(d, "%Y-%m-%d").date() for d, _ in cashflows]
        amounts = [a for _, a in cashflows]
        t0      = dates[0]
        days    = [(d - t0).days for d in dates]

        def npv(rate):
            return sum(a / ((1 + rate) ** (d / 365.0)) for a, d in zip(amounts, days))

        # Bisect between -0.999 and 100 (i.e. -99.9% to 10000% return)
        lo, hi = -0.999, 100.0
        for _ in range(300):
            mid = (lo + hi) / 2
            val = npv(mid)
            if abs(val) < 0.01:
                return round(mid * 100, 2)
            if val > 0:
                lo = mid
            else:
                hi = mid
        return round(((lo + hi) / 2) * 100, 2)
    except Exception:
        return None


def compute_scheme_xirr(transactions, current_value, valuation_date):
    """Build cashflow list from CAS transactions and compute XIRR."""
    cashflows = []
    for txn in transactions:
        try:
            date   = txn.get("date", "")
            amount = float(txn.get("amount") or 0)
            ttype  = (txn.get("type") or "").upper()
            if not date or not amount:
                continue
            # Purchases/SIPs are outflows (negative), redemptions are inflows (positive)
            if any(k in ttype for k in ["PURCHASE", "SIP", "SWITCH_IN", "REINVEST"]):
                cashflows.append((date, -abs(amount)))
            elif any(k in ttype for k in ["REDEMPTION", "SWITCH_OUT"]):
                cashflows.append((date, abs(amount)))
        except Exception:
            continue

    if not cashflows:
        return None

    # Add current value as final inflow
    try:
        cashflows.append((valuation_date, float(current_value)))
        cashflows.sort(key=lambda x: x[0])
        return xirr(cashflows)
    except Exception:
        return None


def detect_sip_amount(transactions):
    """
    Detect active recurring SIP amount from transaction history.
    Returns None if SIP is cancelled or no recurring pattern found.
    """
    from collections import Counter

    # Check if SIP was cancelled — only look at the very last 2 transactions
    # A mid-history "Cancelled" is just a bounced instalment, not SIP termination
    recent = transactions[-2:] if len(transactions) >= 2 else transactions
    for txn in recent:
        ttype = (txn.get("type") or "").upper()
        tdesc = (txn.get("description") or txn.get("narration") or "").upper()
        if any(k in ttype or k in tdesc for k in [
            "SIPCANCELLED", "SIP_CANCEL", "SIP CANCEL",
            "SIPCANCELED"
        ]):
            return None  # SIP is no longer active

    sip_amounts = []
    for txn in transactions:
        ttype  = (txn.get("type") or "").upper()
        tdesc  = (txn.get("description") or txn.get("narration") or "").upper()
        amount = float(txn.get("amount") or 0)

        if amount <= 0:
            continue

        # Skip failed / invalid / reversed transactions
        if any(k in tdesc for k in ["INVALID", "FAILED", "REVERSED", "REJECTED", "CANCELL", "CANCELLED"]):
            continue

        type_is_sip = any(k in ttype for k in [
            "SIP", "SYSTEMATIC", "PURCHASE_SIP", "PURCHASE",
            "SWITCH_IN", "REINVEST"
        ])
        desc_is_sip = any(k in tdesc for k in [
            "SYSTEMATIC INVESTMENT", "SYSTEMATIC PURCHASE",
            "SIP PURCHASE", "SIP INSTALMENT",
            "SYS. INVESTMENT", "SYS INVESTMENT",
            "PURCHASE SIP", "INSTALMENT", "PURCHASE SYSTEMATIC"
        ])

        if type_is_sip or desc_is_sip:
            rounded = round(amount / 100) * 100
            if rounded > 0:
                sip_amounts.append(rounded)

    if not sip_amounts:
        return None

    # Use the most recent recurring amount (last 6 months) rather than all-time
    # In case SIP amount changed, recent takes precedence
    recent_sips = sip_amounts[-6:] if len(sip_amounts) >= 6 else sip_amounts
    most_common, count = Counter(recent_sips).most_common(1)[0]
    return most_common if count >= 2 else None


# ================================================================
#  CAS ROUTES
# ================================================================
@app.route("/api/families/<family_id>/members/<member_id>/cas/upload", methods=["POST"])
def upload_cas(family_id, member_id):
    """Advisor uploads CAS PDF for a member. Accepts base64-encoded PDF + password."""
    auth = require_auth("advisor")
    if auth: return auth

    if not CASPARSER_AVAILABLE:
        return jsonify({"error": "casparser not installed. Add 'casparser' to requirements.txt and redeploy."}), 503

    data     = request.json
    pdf_b64  = data.get("pdf_data", "")
    password = data.get("password", "")

    if not pdf_b64:
        return jsonify({"error": "No PDF data provided"}), 400

    # Decode base64 → temp file
    try:
        if "," in pdf_b64:
            pdf_b64 = pdf_b64.split(",", 1)[1]
        # Strip any whitespace/newlines that browsers may add
        pdf_b64 = pdf_b64.strip().replace("\n", "").replace("\r", "")
        pdf_bytes = base64.b64decode(pdf_b64)
        # Quick sanity check — PDFs start with %PDF
        if not pdf_bytes.startswith(b"%PDF"):
            return jsonify({"error": "File does not appear to be a valid PDF. Please upload a CAS PDF file."}), 400
    except Exception as e:
        return jsonify({"error": f"Invalid file data: {str(e)}"}), 400

    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(pdf_bytes)
            tmp_path = tmp.name

        # output="json" returns a JSON string — avoids Pydantic model handling
        json_str = casparser.read_cas_pdf(tmp_path, password or "", output="json")
        os.unlink(tmp_path)
        # casparser serialises dates as "YYYY-MM-DD" strings in JSON output — safe to parse directly
        result = json.loads(json_str)
    except Exception as e:
        try: os.unlink(tmp_path)
        except: pass
        err_msg = str(e)
        print(f"[CAS PARSE ERROR] {err_msg}")  # visible in Railway logs
        if "password" in err_msg.lower() or "decrypt" in err_msg.lower() or "incorrect" in err_msg.lower():
            return jsonify({"error": "Incorrect PDF password. Please check and try again."}), 400
        if "encrypted" in err_msg.lower():
            return jsonify({"error": "PDF is password-protected. Please enter the correct password."}), 400
        if "pymupdf" in err_msg.lower() or "mupdf" in err_msg.lower():
            return jsonify({"error": "Server missing PyMuPDF dependency. Add 'pymupdf' to requirements.txt and redeploy."}), 503
        if "header" in err_msg.lower() or "parsing cas" in err_msg.lower():
            return jsonify({"error": "This appears to be a CDSL or NSDL demat CAS — these are not supported. Please upload a Detailed CAS from CAMS (camsonline.com) or KFintech (kfintech.com) instead."}), 400
        return jsonify({"error": f"Failed to parse CAS: {err_msg}"}), 400

    # Process parsed data — compute XIRR and detect SIPs
    cas_type = result.get("file_type") or "UNKNOWN"
    folios   = result.get("folios") or []
    schemes  = []

    for folio in folios:
        amc = folio.get("amc") or ""
        for scheme in (folio.get("schemes") or []):
            valuation    = scheme.get("valuation") or {}
            transactions = scheme.get("transactions") or []
            current_val  = float(valuation.get("value") or 0)
            cost_val     = float(valuation.get("cost") or 0)
            val_date     = str(valuation.get("date") or "")
            units        = float(scheme.get("close") or 0)

            scheme_xirr  = compute_scheme_xirr(transactions, current_val, val_date) if current_val else None
            sip_amount   = detect_sip_amount(transactions)

            # Temp debug — remove after confirming SIP detection works
            if transactions:
                sample = [(t.get("type",""), str(t.get("amount",""))[:8]) for t in transactions[:3]]
                print(f"[SIP] {scheme.get('scheme','')[:35]} → sip={sip_amount} | txn samples: {sample}")

            gain     = (current_val - cost_val) if current_val and cost_val else None
            gain_pct = round((gain / cost_val * 100), 2) if gain and cost_val else None

            schemes.append({
                "amc"          : amc,
                "scheme"       : scheme.get("scheme", ""),
                "isin"         : scheme.get("isin", ""),
                "folio"        : folio.get("folio", ""),
                "units"        : round(float(units), 4),
                "nav"          : valuation.get("nav", 0),
                "current_value": round(float(current_val), 2),
                "cost"         : round(float(cost_val), 2),
                "gain"         : round(float(gain), 2) if gain is not None else None,
                "gain_pct"     : gain_pct,
                "xirr"         : scheme_xirr,
                "sip_amount"   : sip_amount,
                "valuation_date": val_date,
                "txn_count"    : len(transactions),
                "type"         : scheme.get("type", ""),
            })

    # Summary
    total_value  = sum(s["current_value"] for s in schemes)
    total_cost   = sum(s["cost"] for s in schemes)
    total_sip    = sum(s["sip_amount"] for s in schemes if s["sip_amount"])
    active_sips  = [s for s in schemes if s["sip_amount"]]

    investor = result.get("investor_info", {})
    parsed   = {
        "cas_type"     : cas_type,
        "investor"     : investor,
        "statement_period": result.get("statement_period", {}),
        "schemes"      : schemes,
        "summary": {
            "total_value" : round(total_value, 2),
            "total_cost"  : round(total_cost, 2),
            "total_gain"  : round(total_value - total_cost, 2),
            "gain_pct"    : round((total_value - total_cost) / total_cost * 100, 2) if total_cost else 0,
            "total_sip"   : total_sip,
            "active_sips" : len(active_sips),
            "scheme_count": len(schemes),
            "folio_count" : len(folios),
        }
    }

    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM cas_portfolios WHERE member_id=?", (member_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE cas_portfolios SET parsed_data=?,cas_type=?,uploaded_at=? WHERE member_id=?",
                (json.dumps(parsed), cas_type, now, member_id)
            )
        else:
            conn.execute(
                "INSERT INTO cas_portfolios (id,family_id,member_id,cas_type,parsed_data,uploaded_at) VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), family_id, member_id, cas_type, json.dumps(parsed), now)
            )
        conn.commit()
        return jsonify({"status": "success", "summary": parsed["summary"],
                        "cas_type": cas_type, "uploaded_at": now})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": f"Storage failed: {str(e)}"}), 500
    finally:
        conn.close()


@app.route("/api/families/<family_id>/members/<member_id>/cas", methods=["GET"])
def get_cas(family_id, member_id):
    auth = require_auth()
    if auth: return auth

    session = get_session()
    if session["role"] == "client" and session.get("family_id") != family_id:
        return jsonify({"error": "Access denied"}), 403

    conn = get_db()
    row  = conn.execute(
        "SELECT * FROM cas_portfolios WHERE member_id=?", (member_id,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"data": None})
    return jsonify({"data": json.loads(row["parsed_data"]), "uploaded_at": row["uploaded_at"]})


@app.route("/api/families/<family_id>/cas", methods=["GET"])
def get_family_cas(family_id):
    """Get CAS data for all members of a family (combined view)."""
    auth = require_auth()
    if auth: return auth

    session = get_session()
    if session["role"] == "client" and session.get("family_id") != family_id:
        return jsonify({"error": "Access denied"}), 403

    conn     = get_db()
    members  = conn.execute(
        "SELECT id, name FROM family_members WHERE family_id=?", (family_id,)
    ).fetchall()
    rows     = conn.execute(
        "SELECT member_id, parsed_data, uploaded_at FROM cas_portfolios WHERE family_id=?",
        (family_id,)
    ).fetchall()
    conn.close()

    member_map = {m["id"]: m["name"] for m in members}
    result     = {}
    for row in rows:
        mid  = row["member_id"]
        data = json.loads(row["parsed_data"])
        result[mid] = {
            "member_name": member_map.get(mid, "Unknown"),
            "uploaded_at": row["uploaded_at"],
            **data
        }
    return jsonify(result)


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
