"""
SkillSwap data layer.
SQLite-backed store with schema, queries, matching engine and trust services.
"""
import sqlite3, json, hashlib, hmac, secrets, os, time
from datetime import date, datetime

DB_PATH = os.environ.get("SS_DB_PATH", "/home/user/workspace/skillswap/backend/skillswap.db")

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
def conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    dob TEXT NOT NULL,
    location TEXT NOT NULL,
    bio TEXT DEFAULT '',
    avatar_color TEXT DEFAULT 'teal',
    age_verified INTEGER DEFAULT 0,
    email_verified INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
    is_seed INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    availability TEXT DEFAULT '{}',
    theme TEXT DEFAULT 'light',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS skills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    icon TEXT DEFAULT '•',
    custom INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_skills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    skill_id INTEGER NOT NULL,
    direction TEXT NOT NULL,  -- 'teach' or 'learn'
    level TEXT DEFAULT 'Intermediate',
    verification TEXT DEFAULT 'none',  -- none/claimed/verified
    created_at TEXT NOT NULL,
    UNIQUE(user_id, skill_id, direction),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(skill_id) REFERENCES skills(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS swaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending/accepted/active/completed/declined/cancelled
    match_pct INTEGER DEFAULT 0,
    offered_skills TEXT DEFAULT '[]',
    wanted_skills TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    accepted_at TEXT,
    completed_at TEXT,
    FOREIGN KEY(requester_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(target_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    swap_id INTEGER NOT NULL,
    created_by INTEGER NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    duration INTEGER DEFAULT 60,
    session_type TEXT DEFAULT 'online',  -- online/supervised
    status TEXT DEFAULT 'scheduled',  -- scheduled/completed/cancelled
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY(swap_id) REFERENCES swaps(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    swap_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    read_state INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(swap_id) REFERENCES swaps(id) ON DELETE CASCADE,
    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    swap_id INTEGER NOT NULL,
    rater_id INTEGER NOT NULL,
    ratee_id INTEGER NOT NULL,
    teaching_quality INTEGER NOT NULL,
    reliability INTEGER NOT NULL,
    communication INTEGER NOT NULL,
    knowledge INTEGER NOT NULL,
    feedback TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(swap_id, rater_id),
    FOREIGN KEY(swap_id) REFERENCES swaps(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, target_id)
);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, target_id)
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL,
    reported_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'open',  -- open/reviewing/warned/restricted/suspended/resolved
    severity TEXT DEFAULT 'low',  -- low/medium/high
    admin_action TEXT DEFAULT '',
    admin_notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY(reported_id) REFERENCES users(id) ON DELETE CASCADE
);
"""

def init_db():
    with conn() as c:
        c.executescript(SCHEMA)

def now():
    """UTC timestamp string."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150000)
    return dk.hex(), salt

def verify_password(password, stored_hash, salt):
    dk, _ = hash_password(password, salt)
    return hmac.compare_digest(dk, stored_hash)

# sessions are in-memory tokens -> user_id
_SESSIONS = {}

def create_session(user_id, remember=False):
    token = secrets.token_urlsafe(32)
    _SESSIONS[token] = {"uid": user_id, "created": time.time(), "remember": remember}
    return token

def session_user(token):
    if not token:
        return None
    s = _SESSIONS.get(token)
    if not s:
        return None
    # sessions last 7 days (30 days if remember)
    ttl = 86400 * (30 if s.get("remember") else 7)
    if time.time() - s["created"] > ttl:
        _SESSIONS.pop(token, None)
        return None
    return s["uid"]

def destroy_session(token):
    _SESSIONS.pop(token, None)

# ---------------------------------------------------------------------------
# Age helpers
# ---------------------------------------------------------------------------
def age_from_dob(dob_str):
    try:
        d = datetime.strptime(dob_str, "%Y-%m-%d").date()
    except Exception:
        return None
    today = date.today()
    a = today.year - d.year - ((today.month, today.day) < (d.month, d.day))
    return a

def age_range_from_age(age):
    if age is None:
        return "Unknown"
    if age <= 14:
        return "13-14"
    if age <= 17:
        return "15-17"
    if age <= 24:
        return "18-24"
    if age <= 34:
        return "25-34"
    return "35+"

def age_range_from_dob(dob_str):
    return age_range_from_age(age_from_dob(dob_str))

# ---------------------------------------------------------------------------
# Row serialization
# ---------------------------------------------------------------------------
def skill_row(c, s):
    return {"id": s["id"], "name": s["name"], "category": s["category"], "icon": s["icon"], "custom": bool(s["custom"])}

def public_user(c, u):
    """Public-facing profile data. Never includes DOB, password, email, admin-only info."""
    age = age_from_dob(u["dob"])
    age_range = age_range_from_age(age)
    # gather skills
    teach = []
    learn = []
    for r in c.execute("SELECT * FROM user_skills WHERE user_id=? ORDER BY id", (u["id"],)):
        sk = c.execute("SELECT * FROM skills WHERE id=?", (r["skill_id"],)).fetchone()
        if not sk:
            continue
        item = {"id": sk["id"], "name": sk["name"], "category": sk["category"], "icon": sk["icon"],
                "level": r["level"], "verification": r["verification"]}
        if r["direction"] == "teach":
            teach.append(item)
        else:
            learn.append(item)
    fav_count = c.execute("SELECT COUNT(*) n FROM favorites WHERE target_id=?", (u["id"],)).fetchone()["n"]
    completed = c.execute("SELECT COUNT(*) n FROM swaps WHERE status='completed' AND (requester_id=? OR target_id=?)", (u["id"], u["id"])).fetchone()["n"]
    ratings = get_ratings_for(c, u["id"])
    trust = compute_trust(c, u["id"])
    return {
        "id": u["id"],
        "name": u["name"],
        "username": u["username"],
        "location": u["location"],
        "bio": u["bio"],
        "avatar_color": u["avatar_color"],
        "age": age if age is not None else None,
        "age_range": age_range,
        "age_verified": bool(u["age_verified"]),
        "email_verified": bool(u["email_verified"]),
        "is_seed": bool(u["is_seed"]),
        "is_admin": bool(u["is_admin"]),
        "status": u["status"],
        "teach_skills": teach,
        "learn_skills": learn,
        "availability": json.loads(u["availability"] or "{}"),
        "completed_swaps": completed,
        "favorites_count": fav_count,
        "ratings": ratings,
        "avg_rating": round(sum(r["overall"] for r in ratings) / len(ratings), 1) if ratings else None,
        "ratings_count": len(ratings),
        "trust": trust,
        "created_at": u["created_at"],
    }

def private_user(c, u):
    """Full private data for the logged-in user."""
    pub = public_user(c, u)
    pub.update({
        "email": u["email"],
        "dob": u["dob"],
        "theme": u["theme"],
    })
    return pub

# ---------------------------------------------------------------------------
# Skills
# ---------------------------------------------------------------------------
def get_skill_catalog(c):
    rows = c.execute("SELECT * FROM skills ORDER BY category, name").fetchall()
    return [skill_row(c, r) for r in rows]

def skill_tree(c):
    cats = {}
    for r in c.execute("SELECT * FROM skills ORDER BY category, name").fetchall():
        cats.setdefault(r["category"], []).append(skill_row(c, r))
    return cats

def find_or_create_skill(c, name, category, icon="•", custom=False):
    name = name.strip()
    row = c.execute("SELECT * FROM skills WHERE lower(name)=lower(?)", (name,)).fetchone()
    if row:
        return row["id"]
    cur = c.execute("INSERT INTO skills(name, category, icon, custom) VALUES(?,?,?,?)", (name, category, icon, 1 if custom else 0))
    return cur.lastrowid

# ---------------------------------------------------------------------------
# Trust system
# ---------------------------------------------------------------------------
def compute_trust(c, user_id):
    u = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        return {"level": "new", "score": 0, "factors": {}}
    email_v = bool(u["email_verified"])
    age_v = bool(u["age_verified"])
    completed = c.execute("SELECT COUNT(*) n FROM swaps WHERE status='completed' AND (requester_id=? OR target_id=?)", (user_id, user_id)).fetchone()["n"]
    sessions_done = c.execute("SELECT COUNT(*) n FROM sessions WHERE status='completed' AND created_by=?", (user_id,)).fetchone()["n"]
    ratings = get_ratings_for(c, user_id)
    avg = (sum(r["overall"] for r in ratings) / len(ratings)) if ratings else 0
    cancellations = c.execute("SELECT COUNT(*) n FROM swaps WHERE status='cancelled' AND requester_id=?", (user_id,)).fetchone()["n"]
    reports = c.execute("SELECT COUNT(*) n FROM reports WHERE reported_id=? AND status NOT IN ('resolved','open')", (user_id,)).fetchone()["n"]
    open_reports = c.execute("SELECT COUNT(*) n FROM reports WHERE reported_id=? AND status='open'", (user_id,)).fetchone()["n"]
    account_age_days = (datetime.utcnow() - datetime.strptime(u["created_at"], "%Y-%m-%dT%H:%M:%SZ")).days if u["created_at"] else 0

    # score 0-100
    score = 0
    score += 12 if email_v else 0
    score += 8 if age_v else 0
    score += min(completed * 8, 24)
    score += min(sessions_done * 3, 9)
    score += min(avg * 2, 20)
    score += min(account_age_days * 0.5, 10)
    score -= min(cancellations * 4, 16)
    score -= min(reports * 8, 16)
    score = max(0, min(100, int(round(score))))

    if u["status"] == "suspended":
        level = "suspended"
    elif u["status"] == "restricted":
        level = "restricted"
    elif score >= 65 and completed >= 3 and email_v:
        level = "trusted"
    elif completed >= 1 or score >= 25:
        level = "established"
    else:
        level = "new"

    return {
        "level": level,
        "score": score,
        "factors": {
            "email_verified": email_v,
            "age_verified": age_v,
            "completed_swaps": completed,
            "sessions_completed": sessions_done,
            "avg_rating": round(avg, 1) if ratings else None,
            "ratings_count": len(ratings),
            "cancellations": cancellations,
            "active_reports": open_reports,
            "actioned_reports": reports,
            "account_age_days": account_age_days,
        }
    }

def get_ratings_for(c, user_id):
    rows = c.execute("SELECT * FROM ratings WHERE ratee_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    out = []
    for r in rows:
        overall = round((r["teaching_quality"] + r["reliability"] + r["communication"] + r["knowledge"]) / 4, 1)
        rater = c.execute("SELECT name, username, avatar_color FROM users WHERE id=?", (r["rater_id"],)).fetchone()
        out.append({
            "swap_id": r["swap_id"], "rater": dict(rater) if rater else None,
            "teaching_quality": r["teaching_quality"], "reliability": r["reliability"],
            "communication": r["communication"], "knowledge": r["knowledge"],
            "overall": overall, "feedback": r["feedback"], "created_at": r["created_at"],
        })
    return out

# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------
LEVEL_RANK = {"Beginner": 1, "Intermediate": 2, "Advanced": 3, "Expert": 4}

def compute_match(c, a_id, b_id):
    a = public_user(c, c.execute("SELECT * FROM users WHERE id=?", (a_id,)).fetchone())
    b = public_user(c, c.execute("SELECT * FROM users WHERE id=?", (b_id,)).fetchone())
    if not a or not b:
        return {"pct": 0, "perfect": False, "factors": {}}

    a_teach = {s["id"]: s for s in a["teach_skills"]}
    a_learn = {s["id"]: s for s in a["learn_skills"]}
    b_teach = {s["id"]: s for s in b["teach_skills"]}
    b_learn = {s["id"]: s for s in b["learn_skills"]}

    # A teaches what B wants to learn
    a_to_b = [s for sid, s in a_teach.items() if sid in b_learn]
    # B teaches what A wants to learn
    b_to_a = [s for sid, s in b_teach.items() if sid in a_learn]

    perfect = bool(a_to_b) and bool(b_to_a)

    # skill fit (0-40)
    if perfect:
        skill_fit = 40
    elif a_to_b or b_to_a:
        skill_fit = 18  # one-way
    else:
        skill_fit = 0

    # shared interests beyond swap (0-10)
    shared = set(a_teach) | set(a_learn)
    shared_b = set(b_teach) | set(b_learn)
    shared_count = len(shared & shared_b)
    shared_score = min(shared_count * 3, 10)

    # level alignment (0-10): avg level of teaching skills offered
    offered = a_to_b + b_to_a
    if offered:
        lvl = sum(LEVEL_RANK.get(s["level"], 2) for s in offered) / len(offered)
        level_score = min(lvl / 4 * 10, 10)
    else:
        level_score = 0

    # age compatibility (0-10)
    ar = a["age_range"]; br = b["age_range"]
    age_order = ["13-14", "15-17", "18-24", "25-34", "35+"]
    if ar in age_order and br in age_order:
        d = abs(age_order.index(ar) - age_order.index(br))
        # minors: same or adjacent group preferred; large gaps penalized
        if d == 0:
            age_score = 10
        elif d == 1:
            age_score = 7
        elif d == 2:
            age_score = 4
        else:
            age_score = 1
    else:
        age_score = 5

    # availability (0-10)
    aa = a["availability"]; ba = b["availability"]
    avail_score = 10 if (aa and ba and (set(aa.get("days", [])) & set(ba.get("days", [])))) else (5 if aa or ba else 0)

    # location (0-10)
    loc_score = 10 if a["location"].lower() == b["location"].lower() else (6 if a["location"].lower().split()[0:1] == b["location"].lower().split()[0:1] else 3)

    # trust of partner (0-10)
    t = b["trust"]["score"]
    trust_score = min(t / 10, 10)

    total = skill_fit + shared_score + level_score + age_score + avail_score + loc_score + trust_score
    pct = max(0, min(100, int(round(total))))

    return {
        "pct": pct,
        "perfect": perfect,
        "factors": {
            "a_teaches_b": [s["name"] for s in a_to_b],
            "b_teaches_a": [s["name"] for s in b_to_a],
            "skill_fit": round(skill_fit / 40 * 100),
            "shared_interests": shared_count,
            "level_alignment": round(level_score / 10 * 100),
            "age_compatibility": round(age_score / 10 * 100),
            "availability": round(avail_score / 10 * 100),
            "location": round(loc_score / 10 * 100),
            "trust": round(trust_score / 10 * 100),
        }
    }

# ---------------------------------------------------------------------------
# Anti-fraud / suspicious patterns
# ---------------------------------------------------------------------------
def suspicious_flags(c, user_id):
    flags = []
    # repeated cancellations
    canc = c.execute("SELECT COUNT(*) n FROM swaps WHERE requester_id=? AND status='cancelled'", (user_id,)).fetchone()["n"]
    if canc >= 3:
        flags.append("Repeated cancellations")
    # many accounts same email domain handled elsewhere; spam messages
    spam = c.execute("SELECT COUNT(*) n FROM messages WHERE sender_id=? AND content IN (SELECT content FROM messages WHERE sender_id=? GROUP BY content HAVING COUNT(*)>3)", (user_id, user_id)).fetchone()["n"]
    if spam > 5:
        flags.append("Spam-like repeated messages")
    # reports
    reps = c.execute("SELECT COUNT(*) n FROM reports WHERE reported_id=?", (user_id,)).fetchone()["n"]
    if reps >= 3:
        flags.append("Multiple reports received")
    # false skill claims (unverified claimed skills)
    claimed = c.execute("SELECT COUNT(*) n FROM user_skills WHERE user_id=? AND verification='claimed'", (user_id,)).fetchone()["n"]
    if claimed >= 5:
        flags.append("Many unverified skill claims")
    return flags
