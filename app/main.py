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

import hashlib
import os
import sqlite3
import traceback
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# A secret used to sign things. Keep it safe.
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', ?, 1)", (hashlib.sha256(b'admin123').hexdigest(),))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('alice', ?, 0)", (hashlib.sha256(b'alicepass').hexdigest(),))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('bob', ?, 0)", (hashlib.sha256(b'bobpass').hexdigest(),))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3,'Bob plans','Bob secret note')")
    db.commit()


init_db()


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- auth helper -----------------------------------------------------------
def current_user(authorization: str = Header(default=None)):
    """Read the token from the Authorization header and return the user row."""
    token = (authorization or "").replace("Bearer ", "")
    row = db.execute("SELECT * FROM users WHERE id = ?", (token,)).fetchone()
    return row


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", (creds.username, hashlib.sha256(creds.password.encode()).hexdigest()))
    db.commit()
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute("SELECT id, password FROM users WHERE username = ?", (creds.username,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No account with that username")
    if row["password"] != hashlib.sha256(creds.password.encode()).hexdigest():
        raise HTTPException(status_code=401, detail="Wrong password")
    return {"token": str(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    if user is None or row["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    if not user or not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = db.execute("SELECT * FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
