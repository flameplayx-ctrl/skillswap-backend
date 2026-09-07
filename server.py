"""
SkillSwap HTTP API server.
Python stdlib http.server + SQLite. No external dependencies.
Run:  python server.py
"""
import json, re, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import store as S
import seed as SEED

PORT = int(os.environ.get("PORT", "8000"))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def jdump(obj):
    return json.dumps(obj, default=str).encode()

class ApiError(Exception):
    def __init__(self, msg, code=400):
        self.msg = msg; self.code = code

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
ROUTES = []  # list of (method, regex, fn)

def route(method, pattern):
    def deco(fn):
        ROUTES.append((method, re.compile("^" + pattern + "$"), fn))
        return fn
    return deco

def parse_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    if not length:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw or b"{}")
    except Exception:
        return {}

def current_user(handler):
    auth = handler.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    uid = S.session_user(token) if token else None
    if not uid:
        return None
    with S.conn() as c:
        u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return u

def require_user(handler):
    u = current_user(handler)
    if not u:
        raise ApiError("Authentication required", 401)
    if u["status"] == "suspended":
        raise ApiError("Your account has been suspended. Contact support.", 403)
    return u

def require_admin(handler):
    u = require_user(handler)
    if not u["is_admin"]:
        raise ApiError("Admin access required", 403)
    return u

# ===========================================================================
# AUTH
# ===========================================================================
@route("POST", "/api/auth/register")
def register(h, m):
    b = parse_body(h)
    name = (b.get("name") or "").strip()
    username = (b.get("username") or "").strip()
    email = (b.get("email") or "").strip().lower()
    password = b.get("password") or ""
    dob = (b.get("dob") or "").strip()
    location = (b.get("location") or "").strip()
    errors = {}
    if len(name) < 2: errors["name"] = "Please enter your name."
    if len(username) < 3: errors["username"] = "Username must be at least 3 characters."
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email): errors["email"] = "Please enter a valid email address."
    if len(password) < 6: errors["password"] = "Password must be at least 6 characters."
    if not dob: errors["dob"] = "Date of birth is required."
    if not location: errors["location"] = "General location is required."
    age = S.age_from_dob(dob) if dob else None
    if age is not None and age < 13: errors["dob"] = "You must be at least 13 to use SkillSwap."
    if not errors:
        with S.conn() as c:
            if c.execute("SELECT 1 FROM users WHERE lower(email)=lower(?)", (email,)).fetchone():
                errors["email"] = "An account with this email already exists."
            elif c.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
                errors["username"] = "This username is already taken."
    if errors:
        raise ApiError({"errors": errors}, 400)
    ph, salt = S.hash_password(password)
    with S.conn() as c:
        cur = c.execute(
            "INSERT INTO users(name, username, email, password_hash, salt, dob, location, bio, avatar_color, status, availability, theme, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, username, email, ph, salt, dob, location, "", "teal", "active",
             json.dumps({"days":[],"hours":""}), "light", S.now()))
        uid = cur.lastrowid
        c.commit()
    token = S.create_session(uid, remember=bool(b.get("remember")))
    return {"token": token, "user": _private(uid), "needs_onboarding": True}

@route("POST", "/api/auth/login")
def login(h, m):
    b = parse_body(h)
    ident = (b.get("identifier") or "").strip().lower()
    password = b.get("password") or ""
    if not ident or not password:
        raise ApiError("Please enter your email/username and password.")
    with S.conn() as c:
        u = c.execute("SELECT * FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)", (ident, ident)).fetchone()
    if not u or not S.verify_password(password, u["password_hash"], u["salt"]):
        raise ApiError("Incorrect email/username or password.", 401)
    if u["status"] == "suspended":
        raise ApiError("Your account has been suspended. Contact support.", 403)
    token = S.create_session(u["id"], remember=bool(b.get("remember")))
    return {"token": token, "user": _private(u["id"])}

@route("POST", "/api/auth/logout")
def logout(h, m):
    auth = h.headers.get("Authorization", "").replace("Bearer ", "").strip()
    S.destroy_session(auth)
    return {"ok": True}

@route("GET", "/api/me")
def me(h, m):
    u = require_user(h)
    return _private(u["id"])

def _private(uid):
    with S.conn() as c:
        u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return S.private_user(c, u)

@route("PUT", "/api/me")
def update_me(h, m):
    u = require_user(h)
    b = parse_body(h)
    allowed = ["name", "bio", "location", "avatar_color", "theme", "dob"]
    sets = []
    vals = []
    for k in allowed:
        if k in b:
            v = b[k]
            if k == "name" and (not v or len(str(v)) < 2):
                raise ApiError("Please enter your name.")
            if k == "location" and (not v):
                raise ApiError("General location is required.")
            if k == "dob" and v:
                age = S.age_from_dob(v)
                if age is None or age < 13:
                    raise ApiError("Please enter a valid date of birth.")
            sets.append(f"{k}=?"); vals.append(v)
    if "availability" in b:
        sets.append("availability=?"); vals.append(json.dumps(b["availability"]))
    if not sets:
        raise ApiError("Nothing to update.")
    vals.append(u["id"])
    with S.conn() as c:
        c.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
        c.commit()
    return _private(u["id"])

@route("POST", "/api/me/send-verification")
def send_verification(h, m):
    u = require_user(h)
    code = str(__import__("random").randint(100000, 999999))
    # store code in memory keyed by user
    S._verify_codes = getattr(S, "_verify_codes", {})
    S._verify_codes[u["id"]] = code
    return {"ok": True, "code": code}  # code returned for demo (simulated email)

@route("POST", "/api/me/verify-email")
def verify_email(h, m):
    u = require_user(h)
    b = parse_body(h)
    code = str(b.get("code") or "")
    codes = getattr(S, "_verify_codes", {})
    if codes.get(u["id"]) != code:
        raise ApiError("Incorrect verification code.")
    with S.conn() as c:
        c.execute("UPDATE users SET email_verified=1 WHERE id=?", (u["id"],))
        c.commit()
    return {"ok": True, "user": _private(u["id"])}

# ===========================================================================
# SKILLS
# ===========================================================================
@route("GET", "/api/skills")
def list_skills(h, m):
    q = parse_qs(urlparse(h.path).query).get("q", [""])[0].lower()
    with S.conn() as c:
        cats = S.get_skill_catalog(c)
    if q:
        cats = [s for s in cats if q in s["name"].lower() or q in s["category"].lower()]
    return {"skills": cats}

@route("GET", "/api/skill-tree")
def skill_tree(h, m):
    with S.conn() as c:
        return {"tree": S.skill_tree(c)}

@route("POST", "/api/skills")
def add_custom_skill(h, m):
    u = require_user(h)
    b = parse_body(h)
    name = (b.get("name") or "").strip()
    category = (b.get("category") or "🔧 Practical Skills").strip()
    if len(name) < 2:
        raise ApiError("Skill name must be at least 2 characters.")
    with S.conn() as c:
        sid = S.find_or_create_skill(c, name, category, "•", custom=True)
        c.commit()
    return {"id": sid, "name": name, "category": category, "icon": "•", "custom": True}

@route("POST", "/api/me/skills")
def set_skill(h, m):
    u = require_user(h)
    b = parse_body(h)
    action = b.get("action")  # add/remove
    direction = b.get("direction")  # teach/learn
    skill_id = b.get("skill_id")
    level = b.get("level", "Intermediate")
    if direction not in ("teach", "learn"):
        raise ApiError("Invalid direction.")
    if action == "add":
        with S.conn() as c:
            c.execute("INSERT OR IGNORE INTO user_skills(user_id, skill_id, direction, level, verification, created_at) VALUES(?,?,?,?,?,?)",
                      (u["id"], skill_id, direction, level, "none", S.now()))
            c.commit()
    elif action == "remove":
        with S.conn() as c:
            c.execute("DELETE FROM user_skills WHERE user_id=? AND skill_id=? AND direction=?", (u["id"], skill_id, direction))
            c.commit()
    return {"ok": True, "user": _private(u["id"])}

@route("POST", "/api/me/skills/verify")
def claim_skill(h, m):
    """Mark a skill as claimed (self-attestation)."""
    u = require_user(h)
    b = parse_body(h)
    with S.conn() as c:
        c.execute("UPDATE user_skills SET verification='claimed' WHERE user_id=? AND skill_id=? AND direction=?",
                  (u["id"], b.get("skill_id"), b.get("direction")))
        c.commit()
    return {"ok": True, "user": _private(u["id"])}

# ===========================================================================
# USERS / DISCOVER / SEARCH
# ===========================================================================
@route("GET", "/api/users/([0-9]+)")
def get_user(h, m):
    u = require_user(h)
    target_id = int(m.group(1))
    # blocked?
    with S.conn() as c:
        if c.execute("SELECT 1 FROM blocks WHERE user_id=? AND target_id=?", (target_id, u["id"])).fetchone():
            raise ApiError("This profile is unavailable.", 404)
        tu = c.execute("SELECT * FROM users WHERE id=? AND status!='suspended'", (target_id,)).fetchone()
        if not tu:
            raise ApiError("User not found.", 404)
        pub = S.public_user(c, tu)
        match = S.compute_match(c, u["id"], target_id)
        is_fav = bool(c.execute("SELECT 1 FROM favorites WHERE user_id=? AND target_id=?", (u["id"], target_id)).fetchone())
        is_blocked = bool(c.execute("SELECT 1 FROM blocks WHERE user_id=? AND target_id=?", (u["id"], target_id)).fetchone())
        existing = c.execute("SELECT * FROM swaps WHERE (requester_id=? AND target_id=?) OR (requester_id=? AND target_id=?)",
                             (u["id"], target_id, target_id, u["id"])).fetchall()
        swap = None
        for s in existing:
            if s["status"] in ("pending","accepted","active"):
                swap = {"id": s["id"], "status": s["status"]}; break
    return {**pub, "match": match, "favorited": is_fav, "blocked": is_blocked, "existing_swap": swap}

@route("GET", "/api/discover")
def discover(h, m):
    u = require_user(h)
    q = parse_qs(urlparse(h.path).query)
    f_skill = q.get("skill", [""])[0].lower()
    f_cat = q.get("category", [""])[0]
    f_age = q.get("age", [""])[0]
    f_level = q.get("level", [""])[0]
    f_loc = q.get("location", [""])[0].lower()
    f_avail = q.get("availability", [""])[0]
    f_min_match = int(q.get("min_match", ["0"])[0])
    f_trust = q.get("trust", [""])[0]
    sort = q.get("sort", ["match"])[0]
    with S.conn() as c:
        blocked = set(r["target_id"] for r in c.execute("SELECT target_id FROM blocks WHERE user_id=?", (u["id"],)).fetchall())
        blocked_me = set(r["user_id"] for r in c.execute("SELECT user_id FROM blocks WHERE target_id=?", (u["id"],)).fetchall())
        rows = c.execute("SELECT * FROM users WHERE id!=? AND status='active' AND is_admin=0", (u["id"],)).fetchall()
        out = []
        for r in rows:
            if r["id"] in blocked or r["id"] in blocked_me:
                continue
            pub = S.public_user(c, r)
            match = S.compute_match(c, u["id"], r["id"])
            # filters
            if f_skill:
                hits = [s for s in pub["teach_skills"]+pub["learn_skills"] if f_skill in s["name"].lower()]
                if not hits: continue
            if f_cat and not any(s["category"]==f_cat for s in pub["teach_skills"]+pub["learn_skills"]): continue
            if f_age and pub["age_range"] != f_age: continue
            if f_level and not any(s["level"]==f_level for s in pub["teach_skills"]): continue
            if f_loc and f_loc not in pub["location"].lower(): continue
            if f_avail and not (pub["availability"] and pub["availability"].get("days")): continue
            if match["pct"] < f_min_match: continue
            if f_trust:
                order = ["new","established","trusted"]
                if order.index(pub["trust"]["level"]) < order.index(f_trust): continue
            out.append({**pub, "match": match})
        if sort == "match":
            out.sort(key=lambda x: x["match"]["pct"], reverse=True)
        elif sort == "trust":
            out.sort(key=lambda x: x["trust"]["score"], reverse=True)
        elif sort == "level":
            out.sort(key=lambda x: max((S.LEVEL_RANK.get(s["level"],2) for s in x["teach_skills"]), default=0), reverse=True)
        elif sort == "availability":
            out.sort(key=lambda x: 1 if (x["availability"] and x["availability"].get("days")) else 0, reverse=True)
    return {"results": out}

@route("GET", "/api/search")
def search(h, m):
    u = require_user(h)
    q = parse_qs(urlparse(h.path).query).get("q", [""])[0].lower()
    sort = parse_qs(urlparse(h.path).query).get("sort", ["match"])[0]
    if not q:
        return {"people_teaching": [], "people_learning": []}
    with S.conn() as c:
        blocked = set(r["target_id"] for r in c.execute("SELECT target_id FROM blocks WHERE user_id=?", (u["id"],)).fetchall())
        blocked_me = set(r["user_id"] for r in c.execute("SELECT user_id FROM blocks WHERE target_id=?", (u["id"],)).fetchall())
        users = c.execute("SELECT * FROM users WHERE id!=? AND status='active' AND is_admin=0", (u["id"],)).fetchall()
        teach, learn = [], []
        for r in users:
            if r["id"] in blocked or r["id"] in blocked_me: continue
            pub = S.public_user(c, r)
            match = S.compute_match(c, u["id"], r["id"])
            t_hit = [s for s in pub["teach_skills"] if q in s["name"].lower() or q in s["category"].lower()]
            l_hit = [s for s in pub["learn_skills"] if q in s["name"].lower() or q in s["category"].lower()]
            if t_hit: teach.append({**pub, "match": match})
            if l_hit: learn.append({**pub, "match": match})
        if sort == "match":
            teach.sort(key=lambda x: x["match"]["pct"], reverse=True)
            learn.sort(key=lambda x: x["match"]["pct"], reverse=True)
        elif sort == "trust":
            teach.sort(key=lambda x: x["trust"]["score"], reverse=True)
            learn.sort(key=lambda x: x["trust"]["score"], reverse=True)
    return {"people_teaching": teach, "people_learning": learn}

# ===========================================================================
# SWAPS
# ===========================================================================
@route("POST", "/api/swaps")
def create_swap(h, m):
    u = require_user(h)
    b = parse_body(h)
    target_id = b.get("target_id")
    offered = b.get("offered_skills", [])
    wanted = b.get("wanted_skills", [])
    if not target_id or not offered or not wanted:
        raise ApiError("Select skills you'll teach and skills you want to learn.")
    with S.conn() as c:
        if c.execute("SELECT 1 FROM blocks WHERE user_id=? AND target_id=?", (target_id, u["id"])).fetchone():
            raise ApiError("You cannot send a request to this user.")
        if c.execute("SELECT 1 FROM blocks WHERE user_id=? AND target_id=?", (u["id"], target_id)).fetchone():
            raise ApiError("You have blocked this user.")
        existing = c.execute("SELECT * FROM swaps WHERE ((requester_id=? AND target_id=?) OR (requester_id=? AND target_id=?)) AND status IN ('pending','accepted','active')",
                             (u["id"], target_id, target_id, u["id"])).fetchone()
        if existing:
            raise ApiError("You already have an active request with this user.")
        match = S.compute_match(c, u["id"], target_id)
        cur = c.execute("INSERT INTO swaps(requester_id, target_id, status, match_pct, offered_skills, wanted_skills, created_at) VALUES(?,?,?,?,?,?,?)",
                       (u["id"], target_id, "pending", match["pct"], json.dumps(offered), json.dumps(wanted), S.now()))
        sid = cur.lastrowid
        c.commit()
    return {"ok": True, "swap_id": sid, "match": match}

@route("GET", "/api/swaps")
def list_swaps(h, m):
    u = require_user(h)
    with S.conn() as c:
        rows = c.execute("SELECT * FROM swaps WHERE requester_id=? OR target_id=? ORDER BY created_at DESC", (u["id"], u["id"])).fetchall()
        out = []
        for s in rows:
            partner_id = s["target_id"] if s["requester_id"]==u["id"] else s["requester_id"]
            p = c.execute("SELECT id,name,username,avatar_color FROM users WHERE id=?", (partner_id,)).fetchone()
            unread = c.execute("SELECT COUNT(*) n FROM messages WHERE swap_id=? AND receiver_id=? AND read_state=0", (s["id"], u["id"])).fetchone()["n"]
            out.append({
                "id": s["id"], "status": s["status"], "match_pct": s["match_pct"],
                "is_requester": s["requester_id"]==u["id"], "partner": dict(p) if p else None,
                "offered_skills": json.loads(s["offered_skills"]), "wanted_skills": json.loads(s["wanted_skills"]),
                "created_at": s["created_at"], "accepted_at": s["accepted_at"], "completed_at": s["completed_at"],
                "unread": unread,
            })
    return {"swaps": out}

@route("GET", "/api/swaps/([0-9]+)")
def get_swap(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or (s["requester_id"]!=u["id"] and s["target_id"]!=u["id"]):
            raise ApiError("Swap not found.", 404)
        partner_id = s["target_id"] if s["requester_id"]==u["id"] else s["requester_id"]
        p = S.public_user(c, c.execute("SELECT * FROM users WHERE id=?", (partner_id,)).fetchone())
        sess = c.execute("SELECT * FROM sessions WHERE swap_id=? ORDER BY date,time", (sid,)).fetchall()
        sessions = [dict(x) for x in sess]
        my_rating = c.execute("SELECT * FROM ratings WHERE swap_id=? AND rater_id=?", (sid, u["id"])).fetchone()
        partner_rated = bool(c.execute("SELECT 1 FROM ratings WHERE swap_id=? AND rater_id=?", (sid, partner_id)).fetchone())
    return {
        "id": s["id"], "status": s["status"], "match_pct": s["match_pct"],
        "is_requester": s["requester_id"]==u["id"], "partner": p,
        "offered_skills": json.loads(s["offered_skills"]), "wanted_skills": json.loads(s["wanted_skills"]),
        "created_at": s["created_at"], "accepted_at": s["accepted_at"], "completed_at": s["completed_at"],
        "sessions": sessions, "my_rating": dict(my_rating) if my_rating else None,
        "partner_rated": partner_rated,
        "is_minor": (S.age_from_dob(u["dob"]) or 99) < 18,
    }

@route("POST", "/api/swaps/([0-9]+)/accept")
def accept_swap(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or s["target_id"]!=u["id"]:
            raise ApiError("Swap not found.", 404)
        if s["status"]!="pending":
            raise ApiError("This request is no longer pending.")
        c.execute("UPDATE swaps SET status='active', accepted_at=? WHERE id=?", (S.now(), sid))
        c.commit()
    return {"ok": True}

@route("POST", "/api/swaps/([0-9]+)/decline")
def decline_swap(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or s["target_id"]!=u["id"]:
            raise ApiError("Swap not found.", 404)
        c.execute("UPDATE swaps SET status='declined' WHERE id=?", (sid,))
        c.commit()
    return {"ok": True}

@route("POST", "/api/swaps/([0-9]+)/cancel")
def cancel_swap(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or (s["requester_id"]!=u["id"] and s["target_id"]!=u["id"]):
            raise ApiError("Swap not found.", 404)
        if s["status"] not in ("pending","active"):
            raise ApiError("This swap can no longer be cancelled.")
        c.execute("UPDATE swaps SET status='cancelled' WHERE id=?", (sid,))
        c.commit()
    return {"ok": True}

@route("POST", "/api/swaps/([0-9]+)/complete")
def complete_swap(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or (s["requester_id"]!=u["id"] and s["target_id"]!=u["id"]):
            raise ApiError("Swap not found.", 404)
        if s["status"]!="active":
            raise ApiError("Only active swaps can be completed.")
        c.execute("UPDATE swaps SET status='completed', completed_at=? WHERE id=?", (S.now(), sid))
        c.commit()
    return {"ok": True}

# ===========================================================================
# SESSIONS
# ===========================================================================
@route("POST", "/api/swaps/([0-9]+)/sessions")
def create_session(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    b = parse_body(h)
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or (s["requester_id"]!=u["id"] and s["target_id"]!=u["id"]):
            raise ApiError("Swap not found.", 404)
        if s["status"] not in ("active","completed"):
            raise ApiError("Schedule sessions only for active swaps.")
        cur = c.execute("INSERT INTO sessions(swap_id, created_by, date, time, duration, session_type, notes, created_at) VALUES(?,?,?,?,?,?,?,?)",
                        (sid, u["id"], b.get("date"), b.get("time"), int(b.get("duration",60)), b.get("session_type","online"), b.get("notes",""), S.now()))
        c.commit()
        nid = cur.lastrowid
    return {"ok": True, "session_id": nid}

@route("POST", "/api/sessions/([0-9]+)/reschedule")
def reschedule_session(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    b = parse_body(h)
    with S.conn() as c:
        sess = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not sess:
            raise ApiError("Session not found.", 404)
        c.execute("UPDATE sessions SET date=?, time=?, duration=?, session_type=? WHERE id=?",
                  (b.get("date"), b.get("time"), int(b.get("duration",60)), b.get("session_type","online"), sid))
        c.commit()
    return {"ok": True}

@route("POST", "/api/sessions/([0-9]+)/cancel")
def cancel_session(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    with S.conn() as c:
        c.execute("UPDATE sessions SET status='cancelled' WHERE id=?", (sid,))
        c.commit()
    return {"ok": True}

@route("POST", "/api/sessions/([0-9]+)/complete")
def complete_session(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    with S.conn() as c:
        c.execute("UPDATE sessions SET status='completed' WHERE id=?", (sid,))
        c.commit()
    return {"ok": True}

# ===========================================================================
# MESSAGES
# ===========================================================================
@route("GET", "/api/conversations")
def conversations(h, m):
    u = require_user(h)
    with S.conn() as c:
        rows = c.execute("SELECT * FROM swaps WHERE (requester_id=? OR target_id=?) AND status IN ('active','completed') ORDER BY id DESC", (u["id"], u["id"])).fetchall()
        out = []
        for s in rows:
            partner_id = s["target_id"] if s["requester_id"]==u["id"] else s["requester_id"]
            p = c.execute("SELECT id,name,username,avatar_color FROM users WHERE id=?", (partner_id,)).fetchone()
            last = c.execute("SELECT * FROM messages WHERE swap_id=? ORDER BY id DESC LIMIT 1", (s["id"],)).fetchone()
            unread = c.execute("SELECT COUNT(*) n FROM messages WHERE swap_id=? AND receiver_id=? AND read_state=0", (s["id"], u["id"])).fetchone()["n"]
            out.append({
                "swap_id": s["id"], "status": s["status"], "partner": dict(p) if p else None,
                "last_message": last["content"][:60] if last else "", "last_at": last["created_at"] if last else None,
                "unread": unread,
            })
    return {"conversations": out}

@route("GET", "/api/swaps/([0-9]+)/messages")
def get_messages(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or (s["requester_id"]!=u["id"] and s["target_id"]!=u["id"]):
            raise ApiError("Conversation not found.", 404)
        # mark messages addressed to me as read
        c.execute("UPDATE messages SET read_state=1 WHERE swap_id=? AND receiver_id=?", (sid, u["id"]))
        c.commit()
        rows = c.execute("SELECT * FROM messages WHERE swap_id=? ORDER BY id ASC", (sid,)).fetchall()
        msgs = []
        for r in rows:
            msgs.append({"id": r["id"], "sender_id": r["sender_id"], "content": r["content"],
                        "created_at": r["created_at"], "mine": r["sender_id"]==u["id"]})
    return {"messages": msgs, "partner_id": s["target_id"] if s["requester_id"]==u["id"] else s["requester_id"]}

@route("POST", "/api/swaps/([0-9]+)/messages")
def send_message(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    b = parse_body(h)
    content = (b.get("content") or "").strip()
    if not content:
        raise ApiError("Message cannot be empty.")
    if len(content) > 2000:
        raise ApiError("Message is too long.")
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or (s["requester_id"]!=u["id"] and s["target_id"]!=u["id"]):
            raise ApiError("Conversation not found.", 404)
        if s["status"] not in ("active","completed"):
            raise ApiError("You can only message active swap partners.")
        partner_id = s["target_id"] if s["requester_id"]==u["id"] else s["requester_id"]
        # blocked?
        if c.execute("SELECT 1 FROM blocks WHERE user_id=? AND target_id=?", (partner_id, u["id"])).fetchone():
            raise ApiError("You cannot message this user.")
        cur = c.execute("INSERT INTO messages(swap_id, sender_id, receiver_id, content, read_state, created_at) VALUES(?,?,?,?,?,?)",
                        (sid, u["id"], partner_id, content, 0, S.now()))
        c.commit()
        mid = cur.lastrowid
    return {"ok": True, "message_id": mid, "created_at": S.now()}

# ===========================================================================
# RATINGS
# ===========================================================================
@route("POST", "/api/swaps/([0-9]+)/rate")
def rate_swap(h, m):
    u = require_user(h)
    sid = int(m.group(1))
    b = parse_body(h)
    with S.conn() as c:
        s = c.execute("SELECT * FROM swaps WHERE id=?", (sid,)).fetchone()
        if not s or (s["requester_id"]!=u["id"] and s["target_id"]!=u["id"]):
            raise ApiError("Swap not found.", 404)
        if s["status"]!="completed":
            raise ApiError("You can only rate completed swaps.")
        partner_id = s["target_id"] if s["requester_id"]==u["id"] else s["requester_id"]
        if c.execute("SELECT 1 FROM ratings WHERE swap_id=? AND rater_id=?", (sid, u["id"])).fetchone():
            raise ApiError("You have already rated this swap.")
        for k in ("teaching_quality","reliability","communication","knowledge"):
            v = int(b.get(k, 0))
            if v < 1 or v > 5:
                raise ApiError(f"Invalid rating for {k}.")
        c.execute("INSERT INTO ratings(swap_id, rater_id, ratee_id, teaching_quality, reliability, communication, knowledge, feedback, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                  (sid, u["id"], partner_id, int(b["teaching_quality"]), int(b["reliability"]), int(b["communication"]), int(b["knowledge"]), b.get("feedback",""), S.now()))
        c.commit()
    return {"ok": True}

# ===========================================================================
# FAVORITES
# ===========================================================================
@route("POST", "/api/favorites/([0-9]+)")
def toggle_favorite(h, m):
    u = require_user(h)
    tid = int(m.group(1))
    with S.conn() as c:
        existing = c.execute("SELECT 1 FROM favorites WHERE user_id=? AND target_id=?", (u["id"], tid)).fetchone()
        if existing:
            c.execute("DELETE FROM favorites WHERE user_id=? AND target_id=?", (u["id"], tid))
            favorited = False
        else:
            c.execute("INSERT INTO favorites(user_id, target_id, created_at) VALUES(?,?,?)", (u["id"], tid, S.now()))
            favorited = True
        c.commit()
    return {"ok": True, "favorited": favorited}

@route("GET", "/api/favorites")
def list_favorites(h, m):
    u = require_user(h)
    with S.conn() as c:
        rows = c.execute("SELECT target_id FROM favorites WHERE user_id=?", (u["id"],)).fetchall()
        out = []
        for r in rows:
            tu = c.execute("SELECT * FROM users WHERE id=?", (r["target_id"],)).fetchone()
            if not tu: continue
            pub = S.public_user(c, tu)
            match = S.compute_match(c, u["id"], tu["id"])
            out.append({**pub, "match": match})
    return {"favorites": out}

# ===========================================================================
# BLOCKS
# ===========================================================================
@route("POST", "/api/blocks/([0-9]+)")
def block_user(h, m):
    u = require_user(h)
    tid = int(m.group(1))
    if tid == u["id"]:
        raise ApiError("You cannot block yourself.")
    with S.conn() as c:
        c.execute("INSERT OR IGNORE INTO blocks(user_id, target_id, created_at) VALUES(?,?,?)", (u["id"], tid, S.now()))
        # cancel any active swap between them
        c.execute("UPDATE swaps SET status='cancelled' WHERE ((requester_id=? AND target_id=?) OR (requester_id=? AND target_id=?)) AND status IN ('pending','active')",
                  (u["id"], tid, tid, u["id"]))
        c.commit()
    return {"ok": True}

@route("DELETE", "/api/blocks/([0-9]+)")
def unblock_user(h, m):
    u = require_user(h)
    tid = int(m.group(1))
    with S.conn() as c:
        c.execute("DELETE FROM blocks WHERE user_id=? AND target_id=?", (u["id"], tid))
        c.commit()
    return {"ok": True}

@route("GET", "/api/blocks")
def list_blocks(h, m):
    u = require_user(h)
    with S.conn() as c:
        rows = c.execute("SELECT target_id FROM blocks WHERE user_id=?", (u["id"],)).fetchall()
        out = []
        for r in rows:
            tu = c.execute("SELECT id,name,username,avatar_color FROM users WHERE id=?", (r["target_id"],)).fetchone()
            if tu: out.append(dict(tu))
    return {"blocks": out}

# ===========================================================================
# REPORTS
# ===========================================================================
@route("POST", "/api/reports")
def create_report(h, m):
    u = require_user(h)
    b = parse_body(h)
    reported_id = b.get("reported_id")
    category = b.get("category")
    description = (b.get("description") or "").strip()
    if not reported_id or not category:
        raise ApiError("Report category and target are required.")
    with S.conn() as c:
        sev = "high" if category in ("Fraud/scam","Safety concern","Harassment","Inappropriate behavior") else "medium"
        c.execute("INSERT INTO reports(reporter_id, reported_id, category, description, severity, created_at) VALUES(?,?,?,?,?,?)",
                  (u["id"], reported_id, category, description, sev, S.now()))
        c.commit()
    return {"ok": True}

# ===========================================================================
# ADMIN
# ===========================================================================
@route("GET", "/api/admin/stats")
def admin_stats(h, m):
    require_admin(h)
    with S.conn() as c:
        stats = {
            "users": c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"],
            "active_swaps": c.execute("SELECT COUNT(*) n FROM swaps WHERE status='active'").fetchone()["n"],
            "completed_swaps": c.execute("SELECT COUNT(*) n FROM swaps WHERE status='completed'").fetchone()["n"],
            "pending_requests": c.execute("SELECT COUNT(*) n FROM swaps WHERE status='pending'").fetchone()["n"],
            "open_reports": c.execute("SELECT COUNT(*) n FROM reports WHERE status='open'").fetchone()["n"],
            "suspended": c.execute("SELECT COUNT(*) n FROM users WHERE status='suspended'").fetchone()["n"],
            "total_skills": c.execute("SELECT COUNT(*) n FROM skills").fetchone()["n"],
        }
    return stats

@route("GET", "/api/admin/reports")
def admin_reports(h, m):
    require_admin(h)
    with S.conn() as c:
        rows = c.execute("SELECT * FROM reports ORDER BY created_at DESC").fetchall()
        out = []
        for r in rows:
            rep = c.execute("SELECT id,name,username FROM users WHERE id=?", (r["reporter_id"],)).fetchone()
            tgt = c.execute("SELECT id,name,username FROM users WHERE id=?", (r["reported_id"],)).fetchone()
            out.append({"id": r["id"], "category": r["category"], "description": r["description"],
                        "reporter": dict(rep) if rep else None, "reported": dict(tgt) if tgt else None,
                        "status": r["status"], "severity": r["severity"], "admin_action": r["admin_action"],
                        "admin_notes": r["admin_notes"], "created_at": r["created_at"]})
    return {"reports": out}

@route("POST", "/api/admin/reports/([0-9]+)/action")
def admin_action(h, m):
    require_admin(h)
    rid = int(m.group(1))
    b = parse_body(h)
    action = b.get("action")  # reviewing/warned/restricted/suspended/resolved
    notes = b.get("notes", "")
    with S.conn() as c:
        r = c.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        if not r:
            raise ApiError("Report not found.", 404)
        c.execute("UPDATE reports SET status=?, admin_action=?, admin_notes=? WHERE id=?", (action, action, notes, rid))
        # apply to reported user
        if action == "restricted":
            c.execute("UPDATE users SET status='restricted' WHERE id=?", (r["reported_id"],))
        elif action == "suspended":
            c.execute("UPDATE users SET status='suspended' WHERE id=?", (r["reported_id"],))
        elif action == "resolved":
            c.execute("UPDATE users SET status='active' WHERE id=?", (r["reported_id"],))
        c.commit()
    return {"ok": True}

@route("GET", "/api/admin/users")
def admin_users(h, m):
    require_admin(h)
    with S.conn() as c:
        rows = c.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        out = []
        for u in rows:
            out.append({"id": u["id"], "name": u["name"], "username": u["username"], "email": u["email"],
                        "status": u["status"], "is_admin": bool(u["is_admin"]), "is_seed": bool(u["is_seed"]),
                        "trust": S.compute_trust(c, u["id"]), "created_at": u["created_at"]})
    return {"users": out}

@route("POST", "/api/admin/users/([0-9]+)/verify-age")
def admin_verify_age(h, m):
    require_admin(h)
    uid = int(m.group(1))
    with S.conn() as c:
        c.execute("UPDATE users SET age_verified=1 WHERE id=?", (uid,))
        c.commit()
    return {"ok": True}

@route("POST", "/api/admin/users/([0-9]+)/restore")
def admin_restore_user(h, m):
    require_admin(h)
    uid = int(m.group(1))
    with S.conn() as c:
        c.execute("UPDATE users SET status='active' WHERE id=?", (uid,))
        c.execute("UPDATE reports SET status='resolved' WHERE reported_id=? AND status!='resolved'", (uid,))
        c.commit()
    return {"ok": True}

# ===========================================================================
# SKILL CHAIN
# ===========================================================================
@route("GET", "/api/skill-chain")
def skill_chain(h, m):
    require_user(h)
    chain = []
    with S.conn() as c:
        completed = c.execute("SELECT * FROM swaps WHERE status='completed' ORDER BY completed_at DESC").fetchall()
        seen = set()
        for s in completed[:50]:
            a = c.execute("SELECT id,name,avatar_color FROM users WHERE id=?", (s["requester_id"],)).fetchone()
            b = c.execute("SELECT id,name,avatar_color FROM users WHERE id=?", (s["target_id"],)).fetchone()
            offered = json.loads(s["offered_skills"])
            wanted = json.loads(s["wanted_skills"])
            teach_name = offered[0]["name"] if offered else "Skill"
            learn_name = wanted[0]["name"] if wanted else "Skill"
            key = (s["id"],)
            if key in seen: continue
            seen.add(key)
            chain.append({
                "from": {"id": a["id"], "name": a["name"], "color": a["avatar_color"]},
                "to": {"id": b["id"], "name": b["name"], "color": b["avatar_color"]},
                "teaches": teach_name, "learns": learn_name, "match_pct": s["match_pct"],
            })
    return {"chain": chain}

# ===========================================================================
# Dashboard extras
# ===========================================================================
@route("GET", "/api/dashboard")
def dashboard(h, m):
    u = require_user(h)
    with S.conn() as c:
        active = c.execute("SELECT COUNT(*) n FROM swaps WHERE status='active' AND (requester_id=? OR target_id=?)", (u["id"], u["id"])).fetchone()["n"]
        completed = c.execute("SELECT COUNT(*) n FROM swaps WHERE status='completed' AND (requester_id=? OR target_id=?)", (u["id"], u["id"])).fetchone()["n"]
        teach = c.execute("SELECT COUNT(*) n FROM user_skills WHERE user_id=? AND direction='teach'", (u["id"],)).fetchone()["n"]
        learn = c.execute("SELECT COUNT(*) n FROM user_skills WHERE user_id=? AND direction='learn'", (u["id"],)).fetchone()["n"]
        # best match from discover
        rows = c.execute("SELECT * FROM users WHERE id!=? AND status='active' AND is_admin=0", (u["id"],)).fetchall()
        blocked = set(r["target_id"] for r in c.execute("SELECT target_id FROM blocks WHERE user_id=?", (u["id"],)).fetchall())
        blocked_me = set(r["user_id"] for r in c.execute("SELECT user_id FROM blocks WHERE target_id=?", (u["id"],)).fetchall())
        best = None; potential = 0
        for r in rows:
            if r["id"] in blocked or r["id"] in blocked_me: continue
            m2 = S.compute_match(c, u["id"], r["id"])
            if m2["pct"] >= 30: potential += 1
            if not best or m2["pct"] > best["match"]["pct"]:
                pub = S.public_user(c, r)
                best = {**pub, "match": m2}
        # unread messages
        unread = c.execute("SELECT COUNT(*) n FROM messages WHERE receiver_id=? AND read_state=0", (u["id"],)).fetchone()["n"]
    return {"active_swaps": active, "completed_swaps": completed, "teaching": teach,
            "learning": learn, "potential_matches": potential, "best_match": best, "unread": unread}

# ===========================================================================
# Handler
# ===========================================================================
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload, ctype="application/json"):
        body = jdump(payload) if not isinstance(payload, (bytes, bytearray)) else payload
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method):
        if method == "OPTIONS":
            return self._send(204, b"")
        path = urlparse(self.path).path
        for (m, rx, fn) in ROUTES:
            match = rx.match(path)
            if match and m == method:
                try:
                    result = fn(self, match)
                    return self._send(200, result)
                except ApiError as e:
                    return self._send(e.code, {"error": e.msg})
                except Exception as e:
                    import traceback; traceback.print_exc()
                    return self._send(500, {"error": f"Server error: {e}"})
        return self._send(404, {"error": "Not found"})

    def do_GET(self): self._dispatch("GET")
    def do_POST(self): self._dispatch("POST")
    def do_PUT(self): self._dispatch("PUT")
    def do_DELETE(self): self._dispatch("DELETE")
    def do_OPTIONS(self): self._dispatch("OPTIONS")

    def log_message(self, *a): pass

def main():
    S.init_db()
    SEED.seed()
    print(f"SkillSwap API listening on :{PORT}")
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.serve_forever()

if __name__ == "__main__":
    main()
