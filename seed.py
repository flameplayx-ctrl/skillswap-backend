"""
SkillSwap seed data.
Idempotent: only seeds when the DB has no users.
"""
import json, hashlib
from datetime import datetime, timezone
import store as S

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# category -> [ (name, icon) ]
CATALOG = {
    "💻 Technology": [
        ("Web Development", "🌐"), ("HTML/CSS", "🎨"), ("JavaScript", "⚙️"), ("React", "⚛️"),
        ("Python", "🐍"), ("Coding", "💻"), ("Roblox Development", "🎮"), ("Game Development", "🕹️"),
        ("Data Science", "📊"), ("Cybersecurity", "🛡️"),
    ],
    "🎨 Creative": [
        ("Drawing", "✏️"), ("Painting", "🖌️"), ("Graphic Design", "🎨"), ("Video Editing", "🎬"),
        ("Animation", "🎞️"), ("Calligraphy", "✒️"), ("UI/UX Design", "📐"),
    ],
    "🎵 Music": [
        ("Guitar", "🎸"), ("Piano", "🎹"), ("Vocals/Singing", "🎤"), ("Music Theory", "🎼"),
        ("Drums", "🥁"), ("Violin", "🎻"), ("Music Production", "🎧"),
    ],
    "📚 Education": [
        ("Math Tutoring", "➗"), ("Science Tutoring", "🔬"), ("Writing", "✍️"), ("Study Skills", "📚"),
        ("Public Speaking", "🗣️"),
    ],
    "🏃 Sports": [
        ("Basketball", "🏀"), ("Soccer", "⚽"), ("Swimming", "🏊"), ("Tennis", "🎾"),
        ("Yoga", "🧘"), ("Martial Arts", "🥋"),
    ],
    "🍳 Cooking": [
        ("Cooking", "🍳"), ("Baking", "🧁"), ("Meal Prep", "🥗"), ("Barista/Coffee", "☕"),
    ],
    "🌎 Languages": [
        ("Spanish", "🇪🇸"), ("Arabic", "🇦🇪"), ("French", "🇫🇷"), ("English", "🇬🇧"),
        ("Mandarin", "🇨🇳"), ("Japanese", "🇯🇵"), ("German", "🇩🇪"),
    ],
    "🔧 Practical Skills": [
        ("Woodworking", "🪵"), ("Sewing", "🧵"), ("Car Repair", "🔧"), ("Gardening", "🌱"),
        ("Home Repair", "🏠"),
    ],
    "🎮 Gaming": [
        ("Roblox", "🟥"), ("Minecraft", "🟩"), ("Esports Coaching", "🏆"), ("Game Strategy", "♟️"),
    ],
    "📸 Photography": [
        ("Photography", "📸"), ("Photo Editing", "🖼️"), ("Portrait Photography", "👤"),
        ("Mobile Photography", "📱"),
    ],
}

# (name, username, email, age_years, location, bio, avatar_color,
#   teach=[(skillname, category, level)], learn=[(skillname, category, level)])
USERS = [
    ("Alex Rivera", "alex", "alex@skillswap.app", 15, "Sharjah, UAE", "High schooler who loves creating videos and wants to pick up guitar.", "blue",
     [("Video Editing","🎨 Creative","Advanced"),("HTML/CSS","💻 Technology","Intermediate"),("Roblox Development","💻 Technology","Intermediate")],
     [("Guitar","🎵 Music","Beginner"),("Photography","📸 Photography","Beginner")]),
    ("Sam Okafor", "sam", "sam@skillswap.app", 15, "Sharjah, UAE", "Guitarist and music theory nerd excited to learn video editing.", "green",
     [("Guitar","🎵 Music","Advanced"),("Music Theory","🎵 Music","Intermediate")],
     [("Video Editing","🎨 Creative","Beginner")]),
    ("Maya Chen", "maya", "maya@skillswap.app", 16, "Dubai, UAE", "Bilingual artist fluent in Spanish, looking to learn Python.", "purple",
     [("Spanish","🌎 Languages","Expert"),("Drawing","🎨 Creative","Advanced")],
     [("Python","💻 Technology","Beginner")]),
    ("Omar Haddad", "omar", "omar@skillswap.app", 17, "Dubai, UAE", "Self-taught coder who teaches Python and wants to practice Spanish.", "orange",
     [("Python","💻 Technology","Advanced"),("Coding","💻 Technology","Advanced")],
     [("Spanish","🌎 Languages","Beginner")]),
    ("Layla Ahmed", "layla", "layla@skillswap.app", 18, "Dubai, UAE", "Photography student and illustrator, wanting to level up in video.", "pink",
     [("Photography","📸 Photography","Advanced"),("Drawing","🎨 Creative","Intermediate")],
     [("Video Editing","🎨 Creative","Beginner")]),
    ("Yusuf Khan", "yusuf", "yusuf@skillswap.app", 20, "Abu Dhabi, UAE", "CS student teaching web dev, dreaming of learning guitar.", "teal",
     [("Python","💻 Technology","Expert"),("Web Development","💻 Technology","Advanced")],
     [("Guitar","🎵 Music","Beginner")]),
    ("Priya Nair", "priya", "priya@skillswap.app", 16, "Sharjah, UAE", "Home baker who loves teaching cooking and wants to learn Spanish.", "yellow",
     [("Cooking","🍳 Cooking","Advanced"),("Baking","🍳 Cooking","Intermediate")],
     [("Spanish","🌎 Languages","Beginner")]),
    ("Daniel Park", "daniel", "daniel@skillswap.app", 24, "Dubai, UAE", "Musician and software engineer, trading guitar for Spanish and Python.", "blue",
     [("Guitar","🎵 Music","Expert"),("Music Theory","🎵 Music","Advanced")],
     [("Spanish","🌎 Languages","Intermediate"),("Python","💻 Technology","Beginner")]),
    ("Aisha Saleh", "aisha", "aisha@skillswap.app", 17, "Sharjah, UAE", "Calligraphy enthusiast teaching Arabic, keen to learn coding.", "purple",
     [("Arabic","🌎 Languages","Advanced"),("Calligraphy","🎨 Creative","Intermediate")],
     [("Python","💻 Technology","Beginner")]),
    ("Carlos Mendez", "carlos", "carlos@skillswap.app", 28, "Dubai, UAE", "Native Spanish speaker and home chef, learning web development.", "orange",
     [("Spanish","🌎 Languages","Expert"),("Cooking","🍳 Cooking","Advanced")],
     [("Web Development","💻 Technology","Beginner")]),
    ("Emma Brooks", "emma", "emma@skillswap.app", 22, "Abu Dhabi, UAE", "Visual storyteller teaching photo & video, wanting to learn guitar.", "pink",
     [("Photography","📸 Photography","Advanced"),("Video Editing","🎨 Creative","Advanced")],
     [("Guitar","🎵 Music","Beginner")]),
    ("Hassan Ali", "hassan", "hassan@skillswap.app", 30, "Dubai, UAE", "Senior dev mentoring in coding, picking up drawing as a hobby.", "teal",
     [("Python","💻 Technology","Expert"),("Coding","💻 Technology","Advanced")],
     [("Drawing","🎨 Creative","Beginner")]),
]

def _dob_for_age(age):
    from datetime import date
    today = date.today()
    y = today.year - age
    return f"{y}-0{((today.month % 9)+1)}-15"[:10]

def seed():
    with S.conn() as c:
        if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] > 0:
            return
        # skills catalog
        for cat, items in CATALOG.items():
            for name, icon in items:
                find_or_create_skill = S.find_or_create_skill
                find_or_create_skill(c, name, cat, icon, custom=False)
        # users
        for (name, username, email, age, loc, bio, color, teach, learn) in USERS:
            ph, salt = S.hash_password("seedpass123")
            cur = c.execute(
                "INSERT INTO users(name, username, email, password_hash, salt, dob, location, bio, avatar_color, age_verified, email_verified, is_seed, status, availability, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, username, email, ph, salt, _dob_for_age(age), loc, bio, color, 1, 1, 1, "active",
                 json.dumps({"days":["Mon","Wed","Sat"],"hours":"evenings"}), now()))
            uid = cur.lastrowid
            for (sname, cat, lvl) in teach:
                sid = S.find_or_create_skill(c, sname, cat, "•", custom=False)
                c.execute("INSERT OR IGNORE INTO user_skills(user_id, skill_id, direction, level, verification, created_at) VALUES(?,?,?,?,?,?)",
                          (uid, sid, "teach", lvl, "verified" if lvl in ("Advanced","Expert") else "claimed", now()))
            for (sname, cat, lvl) in learn:
                sid = S.find_or_create_skill(c, sname, cat, "•", custom=False)
                c.execute("INSERT OR IGNORE INTO user_skills(user_id, skill_id, direction, level, verification, created_at) VALUES(?,?,?,?,?,?)",
                          (uid, sid, "learn", lvl, "none", now()))
        # admin account
        ph, salt = S.hash_password("admin123")
        c.execute(
            "INSERT INTO users(name, username, email, password_hash, salt, dob, location, bio, avatar_color, age_verified, email_verified, is_admin, is_seed, status, availability, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("Admin", "admin", "admin@skillswap.app", ph, salt, _dob_for_age(28), "Dubai, UAE",
             "SkillSwap community moderator.", "slate", 1, 1, 1, 0, "active", json.dumps({}), now()))
        # a couple of completed swaps + ratings for reputation life
        _seed_history(c)
        c.commit()

def _seed_history(c):
    # Alex <-> Sam: completed swap, mutual ratings
    alex = c.execute("SELECT id FROM users WHERE username='alex'").fetchone()["id"]
    sam = c.execute("SELECT id FROM users WHERE username='sam'").fetchone()["id"]
    vid = c.execute("SELECT id FROM skills WHERE name='Video Editing'").fetchone()["id"]
    git = c.execute("SELECT id FROM skills WHERE name='Guitar'").fetchone()["id"]
    cur = c.execute("INSERT INTO swaps(requester_id, target_id, status, match_pct, offered_skills, wanted_skills, created_at, accepted_at, completed_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (alex, sam, "completed", 94, json.dumps([{"id":vid,"name":"Video Editing"}]), json.dumps([{"id":git,"name":"Guitar"}]), now(), now(), now()))
    sid = cur.lastrowid
    c.execute("INSERT INTO ratings(swap_id, rater_id, ratee_id, teaching_quality, reliability, communication, knowledge, feedback, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
              (sid, alex, sam, 5, 5, 4, 5, "Sam was a patient guitar teacher. Great swap!", now()))
    c.execute("INSERT INTO ratings(swap_id, rater_id, ratee_id, teaching_quality, reliability, communication, knowledge, feedback, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
              (sid, sam, alex, 5, 4, 5, 5, "Alex's video editing tips were super helpful.", now()))

if __name__ == "__main__":
    S.init_db()
    seed()
    print("Seeded.")
