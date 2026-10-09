"""
SecureNotes API  —  Week 13 Security Lab (STUDENT VERSION)
Web Systems and Technologies

A tiny notes service: users register, log in, and keep private notes.
It works... but it is NOT secure. Somewhere in this file are SECURITY BUGS
that map to the OWASP Top 10 (2025). Your job is to find them and fix them.

Run it:
    uvicorn app.main:app --reload
Open the interactive docs at:
    http://127.0.0.1:8000/docs

Do NOT change the behaviour students rely on (register, login, notes still work).
Only make it secure. See the lab handout for the task list and rubric.
"""

import sqlite3
import traceback
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os
import hmac
import hashlib
import time
import secrets

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

SECRET_KEY = os.environ["SECRET_KEY"].encode()
ITERATIONS = 600_000
TOKEN_TTL = 30 * 60

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str

class NewNote(BaseModel):
    title: str
    body: str

# --- token --------------------------------------------------------
def _sign(msg: str) -> str:
    return hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()

def make_token(user_id: int) -> str:
    msg = f"{user_id}.{int(time.time()) + TOKEN_TTL}"
    return f"{msg}.{_sign(msg)}"

def parse_token(token: str) -> int | None:
    try:
        user_id, exp, sig = token.split(".")
        if not hmac.compare_digest(_sign(f"{user_id}.{exp}"), sig):
            return None  # forged or tampered
        if int(exp) < time.time():
            return None  # expired
        return int(user_id)
    except ValueError:
        return None

# --- auth helper -----------------------------------------------------------
def current_user(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ")
    user_id = parse_token(token)
    row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    return row

# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything():
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )

# --- password --------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)  
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"{ITERATIONS}${salt.hex()}${key.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        iterations, salt_hex, key_hex = stored.split("$")
        key = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(key, bytes.fromhex(key_hex))
    except ValueError:
        return False

# --- database (SQLite, created fresh on startup) ---------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    # seed: one admin, two normal users, a few notes
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("admin", hash_password("admin123"), 1),
    )
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("alice", hash_password("alicepass"), 0),
    )
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("bob", hash_password("bobpass"), 0),
    )
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3,'Bob plans','Bob secret note')")
    db.commit()

init_db()


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        (creds.username, hash_password(creds.password)),
    )
    db.commit()
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?", (creds.username,)
    ).fetchone()
    if row is None or not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"token": make_token(row["id"]), "token_type": "bearer"}


@app.get("/notes")
def list_my_notes(user=Depends(current_user)):
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user)):
    row = db.execute("SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, user["id"])).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, user=Depends(current_user)):
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(user=Depends(current_user)):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = db.execute("SELECT * FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
