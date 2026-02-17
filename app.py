from __future__ import annotations

import os
import re
import sqlite3
import json
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any

from flask import Flask, g, jsonify, render_template, request, session, send_from_directory
from flask_sock import Sock
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = "nsocial-dev-secret-key-change-me"
sock = Sock(app)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "nsocial.db"
UPLOAD_DIR = DATA_DIR / "uploads"

app.config["MAX_CONTENT_LENGTH"] = 90 * 1024 * 1024

DEFAULT_ADMIN_USERNAME = os.getenv("NSOCIAL_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("NSOCIAL_ADMIN_PASSWORD", "admin12345")
DEFAULT_ADMIN_NAME = os.getenv("NSOCIAL_ADMIN_NAME", "NSocial Admin")
DEFAULT_ICE_SERVERS = [
    {"urls": ["stun:stun.l.google.com:19302"]},
    {"urls": ["stun:stun1.l.google.com:19302"]},
    {"urls": ["stun:stun2.l.google.com:19302"]},
]

CALL_PARTICIPANTS: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
CLIENT_ROOM: dict[str, str] = {}
CALL_CLIENTS: dict[str, Any] = {}
CALL_LOCK = Lock()
REALTIME_CLIENTS: dict[str, Any] = {}
REALTIME_LOCK = Lock()


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _load_ice_servers() -> list[dict[str, Any]]:
    raw = os.getenv("NSOCIAL_ICE_SERVERS_JSON", "").strip()
    if not raw:
        return DEFAULT_ICE_SERVERS

    try:
        parsed = json.loads(raw)
    except Exception:
        return DEFAULT_ICE_SERVERS

    if not isinstance(parsed, list):
        return DEFAULT_ICE_SERVERS

    result: list[dict[str, Any]] = []
    for item in parsed[:10]:
        if not isinstance(item, dict):
            continue
        urls = item.get("urls")
        username = item.get("username")
        credential = item.get("credential")

        if isinstance(urls, str):
            urls_value: str | list[str] = urls[:500]
        elif isinstance(urls, list):
            urls_list = [str(x)[:500] for x in urls if str(x).strip()]
            if not urls_list:
                continue
            urls_value = urls_list
        else:
            continue

        normalized: dict[str, Any] = {"urls": urls_value}
        if isinstance(username, str) and username.strip():
            normalized["username"] = username[:200]
        if isinstance(credential, str) and credential.strip():
            normalized["credential"] = credential[:300]
        result.append(normalized)

    return result or DEFAULT_ICE_SERVERS


ICE_SERVERS = _load_ice_servers()


def _time_short(iso_value: str | None) -> str:
    if not iso_value:
        return ""
    try:
        dt = datetime.fromisoformat(iso_value)
        return dt.strftime("%H:%M")
    except ValueError:
        return ""


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    if slug:
        return slug
    return f"channel-{int(datetime.now().timestamp())}"


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.remote_addr or "unknown")[:64]


def _db() -> sqlite3.Connection:
    if "db" not in g:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def _close_db(_: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row[1] for row in rows}
    if column in existing:
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _ensure_migrations(conn: sqlite3.Connection) -> None:
    _ensure_column(conn, "users", "status_text", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "location", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "website", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "is_admin", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "users", "is_banned", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "users", "banned_reason", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "users", "banned_at", "TEXT")
    _ensure_column(conn, "users", "last_ip", "TEXT NOT NULL DEFAULT ''")

    _ensure_column(conn, "channels", "category", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "channels", "cover_url", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "channels", "is_private", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "channels", "kind", "TEXT NOT NULL DEFAULT 'channel'")
    _ensure_column(conn, "posts", "attachment_name", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "posts", "attachment_url", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "posts", "attachment_type", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "posts", "attachment_size", "INTEGER NOT NULL DEFAULT 0")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS contacts (
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            channel_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_id, contact_user_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(contact_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(channel_id) REFERENCES channels(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contact_blocks (
            user_id INTEGER NOT NULL,
            blocked_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_id, blocked_user_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(blocked_user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    conn.commit()


def _ensure_admin_account(conn: sqlite3.Connection) -> None:
    username = re.sub(r"[^a-zA-Z0-9_]+", "", DEFAULT_ADMIN_USERNAME.strip().lower())[:30] or "admin"
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing is not None:
        conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (existing["id"],))
        conn.commit()
        return

    conn.execute(
        """
        INSERT INTO users (
            name, username, password_hash, bio, avatar_url, status_text, location, website,
            is_admin, is_banned, banned_reason, banned_at, created_at
        )
        VALUES (?, ?, ?, '', '', '', '', '', 1, 0, '', NULL, ?)
        """,
        (DEFAULT_ADMIN_NAME[:60], username, generate_password_hash(DEFAULT_ADMIN_PASSWORD), _now_iso()),
    )
    conn.commit()


def _init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            bio TEXT NOT NULL DEFAULT '',
            avatar_url TEXT NOT NULL DEFAULT '',
            status_text TEXT NOT NULL DEFAULT '',
            location TEXT NOT NULL DEFAULT '',
            website TEXT NOT NULL DEFAULT '',
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_banned INTEGER NOT NULL DEFAULT 0,
            banned_reason TEXT NOT NULL DEFAULT '',
            banned_at TEXT,
            last_ip TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            owner_user_id INTEGER NOT NULL,
            preview TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            cover_url TEXT NOT NULL DEFAULT '',
            is_private INTEGER NOT NULL DEFAULT 0,
            kind TEXT NOT NULL DEFAULT 'channel',
            updated_at TEXT NOT NULL,
            FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS channel_memberships (
            channel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'subscriber')),
            PRIMARY KEY(channel_id, user_id),
            FOREIGN KEY(channel_id) REFERENCES channels(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            attachment_name TEXT NOT NULL DEFAULT '',
            attachment_url TEXT NOT NULL DEFAULT '',
            attachment_type TEXT NOT NULL DEFAULT '',
            attachment_size INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(channel_id) REFERENCES channels(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ip_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_value TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contacts (
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            channel_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_id, contact_user_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(contact_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(channel_id) REFERENCES channels(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contact_blocks (
            user_id INTEGER NOT NULL,
            blocked_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_id, blocked_user_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(blocked_user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    _ensure_migrations(conn)
    _ensure_admin_account(conn)
    conn.close()


with app.app_context():
    _init_db()


@app.errorhandler(413)
def payload_too_large(_: Any) -> Any:
    return jsonify({"error": "Файл слишком большой. Максимум 90 МБ"}), 413


@app.get("/uploads/<path:filename>")
def uploaded_file(filename: str) -> Any:
    return send_from_directory(UPLOAD_DIR, filename)


def _normalize_username(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "", value.strip().lower())[:30]


def _require_user_id() -> int | None:
    user_id = session.get("user_id")
    return user_id if isinstance(user_id, int) else None


def _current_user() -> sqlite3.Row | None:
    user_id = _require_user_id()
    if user_id is None:
        return None

    user = _db().execute(
        """
        SELECT
            id, name, username, bio, avatar_url, status_text, location, website,
            is_admin, is_banned, banned_reason
        FROM users WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    if user is None:
        session.clear()
        return None

    if int(user["is_banned"]) == 1:
        session.clear()
        return None

    return user


def _is_admin(user: sqlite3.Row | None) -> bool:
    return user is not None and int(user["is_admin"]) == 1


def _is_ip_banned(ip: str) -> bool:
    row = _db().execute("SELECT id FROM ip_bans WHERE ip = ?", (ip,)).fetchone()
    return row is not None


def _admin_required_json() -> tuple[sqlite3.Row | None, Any | None]:
    user = _current_user()
    if user is None:
        return None, (jsonify({"error": "Требуется вход"}), 401)
    if not _is_admin(user):
        return None, (jsonify({"error": "Требуются права администратора"}), 403)
    return user, None


def _log_admin_action(
    db: sqlite3.Connection,
    actor_user_id: int,
    action_type: str,
    target_type: str,
    target_value: str,
    details: str = "",
) -> None:
    db.execute(
        """
        INSERT INTO admin_logs (actor_user_id, action_type, target_type, target_value, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            actor_user_id,
            action_type[:64],
            target_type[:64],
            target_value[:120],
            details[:400],
            _now_iso(),
        ),
    )


def _channel_by_slug(slug: str) -> sqlite3.Row | None:
    return _db().execute("SELECT * FROM channels WHERE slug = ?", (slug,)).fetchone()


def _membership(channel_id: int, user_id: int) -> sqlite3.Row | None:
    return _db().execute(
        "SELECT role FROM channel_memberships WHERE channel_id = ? AND user_id = ?",
        (channel_id, user_id),
    ).fetchone()


def _is_contact_blocked(user_id: int, blocked_user_id: int) -> bool:
    row = _db().execute(
        "SELECT 1 FROM contact_blocks WHERE user_id = ? AND blocked_user_id = ?",
        (user_id, blocked_user_id),
    ).fetchone()
    return row is not None


def _contact_by_users(user_id: int, contact_user_id: int) -> sqlite3.Row | None:
    return _db().execute(
        """
        SELECT user_id, contact_user_id, channel_id
        FROM contacts
        WHERE user_id = ? AND contact_user_id = ?
        """,
        (user_id, contact_user_id),
    ).fetchone()


def _contact_payload(user_id: int, contact_user: sqlite3.Row, channel: sqlite3.Row) -> dict[str, Any]:
    payload = _channel_payload(channel, user_id)
    blocked_by_me = _is_contact_blocked(user_id, int(contact_user["id"]))
    blocked_me = _is_contact_blocked(int(contact_user["id"]), user_id)
    can_contact = not blocked_by_me and not blocked_me

    payload.update(
        {
            "kind": "contact",
            "name": contact_user["name"],
            "description": f"@{contact_user['username']}",
            "contact_user_id": int(contact_user["id"]),
            "contact_username": contact_user["username"],
            "contact_avatar_url": contact_user["avatar_url"],
            "blocked_by_me": blocked_by_me,
            "blocked_me": blocked_me,
            "can_post": can_contact,
            "can_call": can_contact,
            "is_subscribed": True,
            "my_role": "contact",
            "can_edit_channel": False,
            "can_delete_channel": False,
        }
    )
    if blocked_by_me:
        payload["preview"] = "Вы заблокировали контакт"
    elif blocked_me:
        payload["preview"] = "Контакт ограничил общение"
    return payload


def _user_by_id(user_id: int) -> sqlite3.Row | None:
    return _db().execute(
        "SELECT id, name, username, avatar_url, is_banned FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def _can_join_call(channel_slug: str, user_id: int) -> bool:
    channel = _channel_by_slug(channel_slug)
    if channel is None:
        return False
    membership = _membership(int(channel["id"]), user_id)
    if membership is None:
        return False
    if (channel["kind"] or "channel") == "contact":
        other_row = _db().execute(
            "SELECT contact_user_id FROM contacts WHERE user_id = ? AND channel_id = ?",
            (user_id, channel["id"]),
        ).fetchone()
        if other_row is None:
            return False
        other_user_id = int(other_row["contact_user_id"])
        if _is_contact_blocked(user_id, other_user_id) or _is_contact_blocked(other_user_id, user_id):
            return False
    return True


def _ws_send(client_id: str, payload: dict[str, Any]) -> bool:
    with CALL_LOCK:
        ws = CALL_CLIENTS.get(client_id)
    if ws is None:
        return False
    try:
        ws.send(json.dumps(payload, ensure_ascii=False))
        return True
    except Exception:
        return False


def _ws_broadcast(room: str, payload: dict[str, Any], exclude: str | None = None) -> None:
    with CALL_LOCK:
        targets = list(CALL_PARTICIPANTS.get(room, {}).keys())
    for client_id in targets:
        if exclude is not None and client_id == exclude:
            continue
        if not _ws_send(client_id, payload):
            _leave_call(client_id, notify=False)


def _realtime_send(client_id: str, payload: dict[str, Any]) -> bool:
    with REALTIME_LOCK:
        ws = REALTIME_CLIENTS.get(client_id)
    if ws is None:
        return False
    try:
        ws.send(json.dumps(payload, ensure_ascii=False))
        return True
    except Exception:
        return False


def _realtime_broadcast(payload: dict[str, Any], exclude: str | None = None) -> None:
    with REALTIME_LOCK:
        targets = list(REALTIME_CLIENTS.keys())
    for client_id in targets:
        if exclude is not None and client_id == exclude:
            continue
        if not _realtime_send(client_id, payload):
            with REALTIME_LOCK:
                REALTIME_CLIENTS.pop(client_id, None)


def _broadcast_state_changed(kind: str, channel_id: str = "", title: str = "", body: str = "") -> None:
    _realtime_broadcast(
        {
            "event": "state_changed",
            "kind": kind[:40],
            "channel_id": channel_id[:80],
            "title": title[:120],
            "body": body[:240],
            "at": _now_iso(),
        }
    )


def _leave_call(client_id: str, notify: bool = True) -> None:
    with CALL_LOCK:
        room = CLIENT_ROOM.pop(client_id, None)
        if room is None:
            return
        participant = CALL_PARTICIPANTS[room].pop(client_id, None)
        room_empty = not CALL_PARTICIPANTS[room]
        if room_empty:
            CALL_PARTICIPANTS.pop(room, None)

    if notify and participant is not None:
        _ws_broadcast(
            room,
            {"event": "call_participant_left", "client_id": client_id},
            exclude=client_id,
        )


def _channel_payload(channel: sqlite3.Row, user_id: int) -> dict[str, Any]:
    db = _db()
    membership = _membership(channel["id"], user_id)
    role = membership["role"] if membership else None

    posts_rows = db.execute(
        """
        SELECT
            p.id, p.text, p.created_at, p.updated_at,
            p.attachment_name, p.attachment_url, p.attachment_type, p.attachment_size,
            u.id AS author_id, u.name, u.username, u.avatar_url
        FROM posts p
        JOIN users u ON u.id = p.user_id
        WHERE p.channel_id = ?
        ORDER BY p.created_at DESC, p.id DESC
        """,
        (channel["id"],),
    ).fetchall()

    posts: list[dict[str, Any]] = []
    for row in posts_rows:
        can_manage = role == "admin" or row["author_id"] == user_id
        posts.append(
            {
                "id": row["id"],
                "user": row["name"],
                "handle": f"@{row['username']}",
                "avatar_url": row["avatar_url"],
                "text": row["text"],
                "attachment_name": row["attachment_name"],
                "attachment_url": row["attachment_url"],
                "attachment_type": row["attachment_type"],
                "attachment_size": int(row["attachment_size"] or 0),
                "sent_at": _time_short(row["created_at"]),
                "edited": row["updated_at"] != row["created_at"],
                "can_edit": bool(can_manage),
                "can_delete": bool(can_manage),
            }
        )

    return {
        "id": channel["slug"],
        "kind": channel["kind"] or "channel",
        "name": channel["name"],
        "description": channel["description"],
        "preview": channel["preview"],
        "time": _time_short(channel["updated_at"]),
        "category": channel["category"],
        "cover_url": channel["cover_url"],
        "is_private": bool(channel["is_private"]),
        "my_role": role,
        "is_subscribed": role is not None,
        "can_edit_channel": role == "admin",
        "can_delete_channel": role == "admin",
        "can_post": role in {"admin", "subscriber"},
        "posts": posts,
    }


def _rebuild_channel_preview(channel_id: int) -> None:
    db = _db()
    row = db.execute(
        """
        SELECT text, attachment_name, created_at
        FROM posts
        WHERE channel_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (channel_id,),
    ).fetchone()
    if row is None:
        db.execute(
            "UPDATE channels SET preview = ?, updated_at = ? WHERE id = ?",
            ("Канал без постов", _now_iso(), channel_id),
        )
        return

    base = row["text"] or (f"Файл: {row['attachment_name']}" if row["attachment_name"] else "Файл")
    preview = base[:52] + ("..." if len(base) > 52 else "")
    db.execute(
        "UPDATE channels SET preview = ?, updated_at = ? WHERE id = ?",
        (preview, row["created_at"], channel_id),
    )


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/admin")
def admin_panel() -> Any:
    user = _current_user()
    if user is None:
        return "Требуется вход", 401
    if not _is_admin(user):
        return "Доступ запрещен", 403
    return render_template("admin.html")


@app.post("/api/auth/register")
def register() -> Any:
    ip = _client_ip()
    if _is_ip_banned(ip):
        return jsonify({"error": "Ваш IP заблокирован администратором"}), 403

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:60]
    username = _normalize_username(str(data.get("username", "")))
    password = str(data.get("password", ""))

    if len(name) < 2:
        return jsonify({"error": "Имя должно быть не короче 2 символов"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username должен быть не короче 3 символов"}), 400
    if len(password) < 6:
        return jsonify({"error": "Пароль должен быть не короче 6 символов"}), 400

    db = _db()
    exists = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if exists:
        return jsonify({"error": "Username уже занят"}), 409

    created_at = _now_iso()
    cursor = db.execute(
        """
        INSERT INTO users (
            name, username, password_hash, bio, avatar_url, status_text, location,
            website, is_admin, is_banned, banned_reason, banned_at, last_ip, created_at
        )
        VALUES (?, ?, ?, '', '', '', '', '', 0, 0, '', NULL, ?, ?)
        """,
        (name, username, generate_password_hash(password), ip, created_at),
    )
    db.commit()

    session["user_id"] = int(cursor.lastrowid)
    return jsonify({"ok": True})


@app.post("/api/auth/login")
def login() -> Any:
    ip = _client_ip()
    if _is_ip_banned(ip):
        return jsonify({"error": "Ваш IP заблокирован администратором"}), 403

    data = request.get_json(silent=True) or {}
    username = _normalize_username(str(data.get("username", "")))
    password = str(data.get("password", ""))

    db = _db()
    row = db.execute(
        "SELECT id, password_hash, is_banned, banned_reason FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Неверный логин или пароль"}), 401

    if int(row["is_banned"]) == 1:
        reason = row["banned_reason"] or "Без указания причины"
        return jsonify({"error": f"Аккаунт заблокирован: {reason}"}), 403

    db.execute("UPDATE users SET last_ip = ? WHERE id = ?", (ip, row["id"]))
    db.commit()
    session["user_id"] = int(row["id"])
    return jsonify({"ok": True})


@app.post("/api/auth/logout")
def logout() -> Any:
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/state")
def get_state() -> Any:
    user = _current_user()
    if user is None:
        return jsonify({"authenticated": False}), 401

    user_id = int(user["id"])
    channels_rows = _db().execute(
        """
        SELECT c.*
        FROM channels c
        LEFT JOIN channel_memberships cm
          ON cm.channel_id = c.id AND cm.user_id = ?
        WHERE (c.is_private = 0 OR cm.user_id IS NOT NULL) AND c.kind = 'channel'
        ORDER BY c.updated_at DESC, c.id DESC
        """,
        (user_id,),
    ).fetchall()

    channels = [_channel_payload(row, user_id) for row in channels_rows]
    contacts_rows = _db().execute(
        """
        SELECT c.contact_user_id, c.channel_id, u.name, u.username, u.avatar_url
        FROM contacts c
        JOIN users u ON u.id = c.contact_user_id
        WHERE c.user_id = ? AND COALESCE(u.is_banned, 0) = 0
        ORDER BY u.name COLLATE NOCASE ASC, u.id ASC
        """,
        (user_id,),
    ).fetchall()
    contacts: list[dict[str, Any]] = []
    for row in contacts_rows:
        channel = _db().execute("SELECT * FROM channels WHERE id = ?", (row["channel_id"],)).fetchone()
        if channel is None:
            continue
        contacts.append(_contact_payload(user_id, row, channel))
    return jsonify(
        {
            "authenticated": True,
            "profile": {
                "id": user_id,
                "name": user["name"],
                "username": user["username"],
                "bio": user["bio"],
                "avatar_url": user["avatar_url"],
                "status_text": user["status_text"],
                "location": user["location"],
                "website": user["website"],
                "is_admin": bool(user["is_admin"]),
            },
            "channels": channels,
            "contacts": contacts,
        }
    )


@app.get("/api/call/config")
def call_config() -> Any:
    user = _current_user()
    if user is None:
        return jsonify({"error": "Требуется вход"}), 401
    return jsonify({"ice_servers": ICE_SERVERS})


@app.get("/api/users/search")
def search_users() -> Any:
    user = _current_user()
    if user is None:
        return jsonify({"error": "Требуется вход"}), 401

    raw_q = str(request.args.get("q", "")).strip()
    q = _normalize_username(raw_q.lstrip("@"))
    if len(q) < 2:
        return jsonify({"items": []})

    user_id = int(user["id"])
    rows = _db().execute(
        """
        SELECT id, name, username, avatar_url
        FROM users
        WHERE id != ?
          AND COALESCE(is_banned, 0) = 0
          AND username LIKE ?
        ORDER BY
          CASE WHEN username = ? THEN 0 ELSE 1 END,
          username COLLATE NOCASE ASC
        LIMIT 20
        """,
        (user_id, f"{q}%", q),
    ).fetchall()

    items: list[dict[str, Any]] = []
    for row in rows:
        target_id = int(row["id"])
        relation = _contact_by_users(user_id, target_id)
        items.append(
            {
                "id": target_id,
                "name": row["name"],
                "username": row["username"],
                "avatar_url": row["avatar_url"],
                "is_contact": relation is not None,
                "blocked_by_me": _is_contact_blocked(user_id, target_id),
                "blocked_me": _is_contact_blocked(target_id, user_id),
            }
        )

    return jsonify({"items": items})


@app.patch("/api/profile")
def update_profile() -> Any:
    user = _current_user()
    if user is None:
        return jsonify({"error": "Требуется вход"}), 401

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", user["name"]))[:60].strip()
    username = _normalize_username(str(data.get("username", user["username"])))
    bio = str(data.get("bio", user["bio"]))[:280].strip()
    avatar_url = str(data.get("avatar_url", user["avatar_url"]))[:120000].strip()
    status_text = str(data.get("status_text", user["status_text"]))[:80].strip()
    location = str(data.get("location", user["location"]))[:80].strip()
    website = str(data.get("website", user["website"]))[:2048].strip()

    if len(name) < 2:
        return jsonify({"error": "Имя должно быть не короче 2 символов"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username должен быть не короче 3 символов"}), 400

    db = _db()
    taken = db.execute(
        "SELECT id FROM users WHERE username = ? AND id != ?",
        (username, user["id"]),
    ).fetchone()
    if taken:
        return jsonify({"error": "Username уже занят"}), 409

    db.execute(
        """
        UPDATE users
        SET name = ?, username = ?, bio = ?, avatar_url = ?, status_text = ?, location = ?, website = ?
        WHERE id = ?
        """,
        (name, username, bio, avatar_url, status_text, location, website, user["id"]),
    )
    db.commit()
    _broadcast_state_changed("profile_updated")

    return jsonify({"ok": True})


@app.post("/api/contacts")
def add_contact() -> Any:
    user = _current_user()
    if user is None:
        return jsonify({"error": "Требуется вход"}), 401

    data = request.get_json(silent=True) or {}
    username = _normalize_username(str(data.get("username", "")))
    if len(username) < 3:
        return jsonify({"error": "Укажите username контакта"}), 400

    db = _db()
    target = db.execute(
        "SELECT id, name, username FROM users WHERE username = ? AND COALESCE(is_banned, 0) = 0",
        (username,),
    ).fetchone()
    if target is None:
        return jsonify({"error": "Пользователь не найден"}), 404

    user_id = int(user["id"])
    target_user_id = int(target["id"])
    if user_id == target_user_id:
        return jsonify({"error": "Нельзя добавить себя в контакты"}), 400

    exists = _contact_by_users(user_id, target_user_id)
    if exists is not None:
        return jsonify({"ok": True})
    reverse = _contact_by_users(target_user_id, user_id)
    if reverse is not None:
        channel_row = db.execute("SELECT slug FROM channels WHERE id = ?", (int(reverse["channel_id"]),)).fetchone()
        db.execute(
            "INSERT INTO contacts (user_id, contact_user_id, channel_id, created_at) VALUES (?, ?, ?, ?)",
            (user_id, target_user_id, int(reverse["channel_id"]), _now_iso()),
        )
        db.commit()
        _broadcast_state_changed("contact_added")
        return jsonify({"ok": True, "channel_id": (channel_row["slug"] if channel_row else "")}), 201

    channel_slug = f"dm-{min(user_id, target_user_id)}-{max(user_id, target_user_id)}-{uuid.uuid4().hex[:8]}"
    now = _now_iso()
    cur = db.execute(
        """
        INSERT INTO channels (
            slug, name, description, owner_user_id, preview, category, cover_url, is_private, kind, updated_at
        )
        VALUES (?, ?, '', ?, 'Чат создан', 'Контакт', '', 1, 'contact', ?)
        """,
        (channel_slug, f"DM {user['username']} - {target['username']}", user_id, now),
    )
    channel_id = int(cur.lastrowid)

    db.execute(
        "INSERT INTO channel_memberships (channel_id, user_id, role) VALUES (?, ?, 'subscriber')",
        (channel_id, user_id),
    )
    db.execute(
        "INSERT INTO channel_memberships (channel_id, user_id, role) VALUES (?, ?, 'subscriber')",
        (channel_id, target_user_id),
    )
    db.execute(
        "INSERT INTO contacts (user_id, contact_user_id, channel_id, created_at) VALUES (?, ?, ?, ?)",
        (user_id, target_user_id, channel_id, now),
    )
    db.execute(
        "INSERT INTO contacts (user_id, contact_user_id, channel_id, created_at) VALUES (?, ?, ?, ?)",
        (target_user_id, user_id, channel_id, now),
    )
    db.commit()
    _broadcast_state_changed("contact_added", channel_slug)
    return jsonify({"ok": True, "channel_id": channel_slug}), 201


@app.delete("/api/contacts/<int:contact_user_id>")
def delete_contact(contact_user_id: int) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    relation = _contact_by_users(user_id, contact_user_id)
    if relation is None:
        return jsonify({"ok": True})

    channel_id = int(relation["channel_id"])
    channel = db.execute("SELECT slug FROM channels WHERE id = ?", (channel_id,)).fetchone()
    channel_slug = channel["slug"] if channel else ""

    db.execute(
        "DELETE FROM contacts WHERE (user_id = ? AND contact_user_id = ?) OR (user_id = ? AND contact_user_id = ?)",
        (user_id, contact_user_id, contact_user_id, user_id),
    )
    db.execute(
        "DELETE FROM contact_blocks WHERE (user_id = ? AND blocked_user_id = ?) OR (user_id = ? AND blocked_user_id = ?)",
        (user_id, contact_user_id, contact_user_id, user_id),
    )
    db.execute("DELETE FROM channels WHERE id = ?", (channel_id,))
    db.commit()
    _broadcast_state_changed("contact_removed", channel_slug)
    return jsonify({"ok": True})


@app.post("/api/contacts/<int:contact_user_id>/block")
def block_contact(contact_user_id: int) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    relation = _contact_by_users(user_id, contact_user_id)
    if relation is None:
        return jsonify({"error": "Контакт не найден"}), 404

    db = _db()
    db.execute(
        """
        INSERT INTO contact_blocks (user_id, blocked_user_id, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, blocked_user_id) DO NOTHING
        """,
        (user_id, contact_user_id, _now_iso()),
    )
    db.commit()
    _broadcast_state_changed("contact_blocked")
    return jsonify({"ok": True})


@app.post("/api/contacts/<int:contact_user_id>/unblock")
def unblock_contact(contact_user_id: int) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    db.execute(
        "DELETE FROM contact_blocks WHERE user_id = ? AND blocked_user_id = ?",
        (user_id, contact_user_id),
    )
    db.commit()
    _broadcast_state_changed("contact_unblocked")
    return jsonify({"ok": True})


@app.post("/api/channels")
def create_channel() -> Any:
    user = _current_user()
    if user is None:
        return jsonify({"error": "Требуется вход"}), 401

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:60]
    description = str(data.get("description", "")).strip()[:180]
    category = str(data.get("category", "")).strip()[:40]
    cover_url = str(data.get("cover_url", "")).strip()[:2048]
    is_private = 1 if bool(data.get("is_private")) else 0
    if len(name) < 2:
        return jsonify({"error": "Название канала должно быть минимум 2 символа"}), 400

    db = _db()
    base_slug = _slugify(name)
    slug = base_slug
    suffix = 2
    while db.execute("SELECT id FROM channels WHERE slug = ?", (slug,)).fetchone() is not None:
        slug = f"{base_slug}-{suffix}"
        suffix += 1

    now = _now_iso()
    cur = db.execute(
        """
        INSERT INTO channels (slug, name, description, owner_user_id, preview, category, cover_url, is_private, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            slug,
            name,
            description,
            user["id"],
            "Канал создан. Опубликуйте первый пост.",
            category,
            cover_url,
            is_private,
            now,
        ),
    )
    channel_id = int(cur.lastrowid)
    db.execute(
        "INSERT INTO channel_memberships (channel_id, user_id, role) VALUES (?, ?, 'admin')",
        (channel_id, user["id"]),
    )
    db.commit()
    _broadcast_state_changed("channel_created", slug)

    return jsonify({"id": slug}), 201


@app.patch("/api/channels/<channel_slug>")
def edit_channel(channel_slug: str) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    channel = _channel_by_slug(channel_slug)
    if channel is None:
        return jsonify({"error": "Канал не найден"}), 404

    membership = _membership(channel["id"], user_id)
    if membership is None or membership["role"] != "admin":
        return jsonify({"error": "Только админ канала может редактировать его"}), 403

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", channel["name"]))[:60].strip()
    description = str(data.get("description", channel["description"]))[:180].strip()
    category = str(data.get("category", channel["category"]))[:40].strip()
    cover_url = str(data.get("cover_url", channel["cover_url"]))[:2048].strip()
    is_private = 1 if bool(data.get("is_private", channel["is_private"])) else 0

    if len(name) < 2:
        return jsonify({"error": "Название канала должно быть минимум 2 символа"}), 400

    db.execute(
        "UPDATE channels SET name = ?, description = ?, category = ?, cover_url = ?, is_private = ? WHERE id = ?",
        (name, description, category, cover_url, is_private, channel["id"]),
    )
    db.commit()
    _broadcast_state_changed("channel_updated", channel_slug)
    return jsonify({"ok": True})


@app.delete("/api/channels/<channel_slug>")
def delete_channel(channel_slug: str) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    channel = _channel_by_slug(channel_slug)
    if channel is None:
        return jsonify({"error": "Канал не найден"}), 404

    membership = _membership(channel["id"], user_id)
    if membership is None or membership["role"] != "admin":
        return jsonify({"error": "Только админ канала может удалить его"}), 403

    db.execute("DELETE FROM channels WHERE id = ?", (channel["id"],))
    db.commit()
    _broadcast_state_changed("channel_deleted", channel_slug)
    return jsonify({"ok": True})


@app.post("/api/channels/<channel_slug>/subscribe")
def subscribe_channel(channel_slug: str) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    channel = _channel_by_slug(channel_slug)
    if channel is None:
        return jsonify({"error": "Канал не найден"}), 404

    if _membership(channel["id"], user_id) is not None:
        return jsonify({"ok": True})

    if int(channel["is_private"]) == 1:
        return jsonify({"error": "Канал приватный. Подписка отключена."}), 403

    db.execute(
        "INSERT INTO channel_memberships (channel_id, user_id, role) VALUES (?, ?, 'subscriber')",
        (channel["id"], user_id),
    )
    db.commit()
    _broadcast_state_changed("channel_subscribed", channel_slug)
    return jsonify({"ok": True})


@app.post("/api/channels/<channel_slug>/unsubscribe")
def unsubscribe_channel(channel_slug: str) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    channel = _channel_by_slug(channel_slug)
    if channel is None:
        return jsonify({"error": "Канал не найден"}), 404

    membership = _membership(channel["id"], user_id)
    if membership is None:
        return jsonify({"ok": True})

    if membership["role"] == "admin":
        admin_count_row = db.execute(
            "SELECT COUNT(*) AS c FROM channel_memberships WHERE channel_id = ? AND role = 'admin'",
            (channel["id"],),
        ).fetchone()
        if int(admin_count_row["c"]) <= 1:
            return jsonify({"error": "Нельзя отписаться: вы единственный админ канала"}), 400

    db.execute(
        "DELETE FROM channel_memberships WHERE channel_id = ? AND user_id = ?",
        (channel["id"], user_id),
    )
    db.commit()
    _broadcast_state_changed("channel_unsubscribed", channel_slug)
    return jsonify({"ok": True})


@app.post("/api/channels/<channel_slug>/posts")
def create_post(channel_slug: str) -> Any:
    user = _current_user()
    if user is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    channel = _channel_by_slug(channel_slug)
    if channel is None:
        return jsonify({"error": "Канал не найден"}), 404

    membership = _membership(channel["id"], int(user["id"]))
    if membership is None:
        return jsonify({"error": "Подпишитесь на канал, чтобы публиковать посты"}), 403
    if (channel["kind"] or "channel") == "contact":
        other = _db().execute(
            "SELECT contact_user_id FROM contacts WHERE user_id = ? AND channel_id = ?",
            (int(user["id"]), channel["id"]),
        ).fetchone()
        if other is None:
            return jsonify({"error": "Контакт не найден"}), 404
        other_user_id = int(other["contact_user_id"])
        if _is_contact_blocked(int(user["id"]), other_user_id):
            return jsonify({"error": "Вы заблокировали этот контакт"}), 403
        if _is_contact_blocked(other_user_id, int(user["id"])):
            return jsonify({"error": "Контакт ограничил сообщения для вас"}), 403

    text = ""
    attachment_name = ""
    attachment_url = ""
    attachment_type = ""
    attachment_size = 0

    if request.content_type and request.content_type.startswith("multipart/form-data"):
        text = str(request.form.get("text", "")).strip()[:1200]
        file = request.files.get("file")
        if file and file.filename:
            safe_name = secure_filename(file.filename)[:200]
            ext = Path(safe_name).suffix[:10]
            file_name = f"{uuid.uuid4().hex}{ext}"
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            file_path = UPLOAD_DIR / file_name
            file.save(file_path)
            attachment_name = safe_name or "file"
            attachment_url = f"/uploads/{file_name}"
            attachment_type = str(file.mimetype or "")[:100]
            try:
                attachment_size = int(file_path.stat().st_size)
            except OSError:
                attachment_size = 0
    else:
        data = request.get_json(silent=True) or {}
        text = str(data.get("text", "")).strip()[:1200]

    if not text and not attachment_url:
        return jsonify({"error": "Добавьте текст или файл"}), 400

    now = _now_iso()
    db.execute(
        """
        INSERT INTO posts (
            channel_id, user_id, text, created_at, updated_at,
            attachment_name, attachment_url, attachment_type, attachment_size
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            channel["id"],
            user["id"],
            text,
            now,
            now,
            attachment_name,
            attachment_url,
            attachment_type,
            attachment_size,
        ),
    )
    preview_base = text or (f"Файл: {attachment_name}" if attachment_name else "Файл")
    preview = preview_base[:52] + ("..." if len(preview_base) > 52 else "")
    db.execute(
        "UPDATE channels SET preview = ?, updated_at = ? WHERE id = ?",
        (preview, now, channel["id"]),
    )
    db.commit()
    if (channel["kind"] or "channel") == "contact":
        _broadcast_state_changed(
            "direct_message_created",
            channel_slug,
            title=f"Новое сообщение от {user['name']}",
            body=(text[:140] if text else f"Файл: {attachment_name or 'вложение'}"),
        )
    else:
        _broadcast_state_changed(
            "post_created",
            channel_slug,
            title=f"Новый пост в {channel['name']}",
            body=(text[:140] if text else f"Файл: {attachment_name or 'вложение'}"),
        )

    return jsonify({"ok": True}), 201


@app.patch("/api/channels/<channel_slug>/posts/<int:post_id>")
def edit_post(channel_slug: str, post_id: int) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    channel = _channel_by_slug(channel_slug)
    if channel is None:
        return jsonify({"error": "Канал не найден"}), 404

    post = db.execute(
        "SELECT id, user_id, attachment_url FROM posts WHERE id = ? AND channel_id = ?",
        (post_id, channel["id"]),
    ).fetchone()
    if post is None:
        return jsonify({"error": "Пост не найден"}), 404

    membership = _membership(channel["id"], user_id)
    is_admin = membership is not None and membership["role"] == "admin"
    if not is_admin and int(post["user_id"]) != user_id:
        return jsonify({"error": "Недостаточно прав"}), 403

    data = request.get_json(silent=True) or {}
    text = str(data.get("text", "")).strip()[:1200]
    if not text and not post["attachment_url"]:
        return jsonify({"error": "Текст поста обязателен"}), 400

    db.execute(
        "UPDATE posts SET text = ?, updated_at = ? WHERE id = ?",
        (text, _now_iso(), post_id),
    )
    _rebuild_channel_preview(channel["id"])
    db.commit()
    _broadcast_state_changed("post_updated", channel_slug)
    return jsonify({"ok": True})


@app.delete("/api/channels/<channel_slug>/posts/<int:post_id>")
def delete_post(channel_slug: str, post_id: int) -> Any:
    user_id = _require_user_id()
    if user_id is None:
        return jsonify({"error": "Требуется вход"}), 401

    db = _db()
    channel = _channel_by_slug(channel_slug)
    if channel is None:
        return jsonify({"error": "Канал не найден"}), 404

    post = db.execute(
        "SELECT id, user_id FROM posts WHERE id = ? AND channel_id = ?",
        (post_id, channel["id"]),
    ).fetchone()
    if post is None:
        return jsonify({"error": "Пост не найден"}), 404

    membership = _membership(channel["id"], user_id)
    is_admin = membership is not None and membership["role"] == "admin"
    if not is_admin and int(post["user_id"]) != user_id:
        return jsonify({"error": "Недостаточно прав"}), 403

    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    _rebuild_channel_preview(channel["id"])
    db.commit()
    _broadcast_state_changed("post_deleted", channel_slug)
    return jsonify({"ok": True})


@sock.route("/ws/realtime")
def ws_realtime(ws: Any) -> None:
    user = _current_user()
    if user is None:
        ws.send(json.dumps({"event": "error", "message": "Требуется вход"}, ensure_ascii=False))
        ws.close()
        return

    client_id = uuid.uuid4().hex
    with REALTIME_LOCK:
        REALTIME_CLIENTS[client_id] = ws
    _realtime_send(client_id, {"event": "rt_ready", "client_id": client_id})

    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break

            try:
                data = json.loads(raw)
            except Exception:
                continue

            if str(data.get("event", "")).strip() == "ping":
                _realtime_send(client_id, {"event": "pong"})
    finally:
        with REALTIME_LOCK:
            REALTIME_CLIENTS.pop(client_id, None)


@app.get("/api/admin/state")
def admin_state() -> Any:
    admin_user, error = _admin_required_json()
    if error is not None:
        return error

    db = _db()
    users_rows = db.execute(
        """
        SELECT id, name, username, is_admin, is_banned, banned_reason, last_ip, created_at
        FROM users
        ORDER BY created_at DESC, id DESC
        """
    ).fetchall()
    users = [
        {
            "id": row["id"],
            "name": row["name"],
            "username": row["username"],
            "is_admin": bool(row["is_admin"]),
            "is_banned": bool(row["is_banned"]),
            "banned_reason": row["banned_reason"],
            "last_ip": row["last_ip"],
            "created_at": row["created_at"],
        }
        for row in users_rows
    ]

    ip_rows = db.execute(
        "SELECT id, ip, reason, created_at FROM ip_bans ORDER BY created_at DESC, id DESC"
    ).fetchall()
    ip_bans = [
        {"id": row["id"], "ip": row["ip"], "reason": row["reason"], "created_at": row["created_at"]}
        for row in ip_rows
    ]

    log_rows = db.execute(
        """
        SELECT l.id, l.action_type, l.target_type, l.target_value, l.details, l.created_at, u.username AS actor_username
        FROM admin_logs l
        JOIN users u ON u.id = l.actor_user_id
        ORDER BY l.created_at DESC, l.id DESC
        LIMIT 200
        """
    ).fetchall()
    logs = [
        {
            "id": row["id"],
            "action_type": row["action_type"],
            "target_type": row["target_type"],
            "target_value": row["target_value"],
            "details": row["details"],
            "created_at": row["created_at"],
            "actor_username": row["actor_username"],
        }
        for row in log_rows
    ]

    return jsonify({"users": users, "ip_bans": ip_bans, "logs": logs, "admin_username": admin_user["username"]})


@app.post("/api/admin/change-password")
def admin_change_password() -> Any:
    admin_user, error = _admin_required_json()
    if error is not None:
        return error

    data = request.get_json(silent=True) or {}
    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))

    if len(new_password) < 8:
        return jsonify({"error": "Новый пароль должен быть не короче 8 символов"}), 400

    db = _db()
    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (admin_user["id"],)).fetchone()
    if row is None:
        return jsonify({"error": "Админ не найден"}), 404

    if not check_password_hash(row["password_hash"], current_password):
        return jsonify({"error": "Текущий пароль неверный"}), 400

    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), admin_user["id"]),
    )
    _log_admin_action(
        db,
        int(admin_user["id"]),
        "change_password",
        "self",
        str(admin_user["id"]),
        "Изменен пароль администратора",
    )
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/admin/users/<int:user_id>/ban")
def admin_ban_user(user_id: int) -> Any:
    admin_user, error = _admin_required_json()
    if error is not None:
        return error

    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason", "")).strip()[:240] or "Нарушение правил"

    db = _db()
    target = db.execute(
        "SELECT id, is_admin FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if target is None:
        return jsonify({"error": "Пользователь не найден"}), 404

    if int(target["is_admin"]) == 1:
        return jsonify({"error": "Нельзя банить администратора"}), 400

    if int(admin_user["id"]) == user_id:
        return jsonify({"error": "Нельзя банить самого себя"}), 400

    db.execute(
        "UPDATE users SET is_banned = 1, banned_reason = ?, banned_at = ? WHERE id = ?",
        (reason, _now_iso(), user_id),
    )
    _log_admin_action(
        db,
        int(admin_user["id"]),
        "ban_user",
        "user",
        str(user_id),
        reason,
    )
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/admin/users/<int:user_id>/unban")
def admin_unban_user(user_id: int) -> Any:
    admin_user, error = _admin_required_json()
    if error is not None:
        return error

    db = _db()
    target = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        return jsonify({"error": "Пользователь не найден"}), 404

    db.execute(
        "UPDATE users SET is_banned = 0, banned_reason = '', banned_at = NULL WHERE id = ?",
        (user_id,),
    )
    _log_admin_action(
        db,
        int(admin_user["id"]),
        "unban_user",
        "user",
        str(user_id),
        "Аккаунт разблокирован",
    )
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/admin/ip-bans")
def admin_add_ip_ban() -> Any:
    admin_user, error = _admin_required_json()
    if error is not None:
        return error

    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()[:64]
    reason = str(data.get("reason", "")).strip()[:240] or "Нарушение правил"

    if not re.match(r"^[0-9a-fA-F:\.]+$", ip):
        return jsonify({"error": "Некорректный IP"}), 400

    db = _db()
    exists = db.execute("SELECT id FROM ip_bans WHERE ip = ?", (ip,)).fetchone()
    if exists is not None:
        return jsonify({"error": "Этот IP уже заблокирован"}), 409

    db.execute(
        "INSERT INTO ip_bans (ip, reason, created_at) VALUES (?, ?, ?)",
        (ip, reason, _now_iso()),
    )
    _log_admin_action(
        db,
        int(admin_user["id"]),
        "ban_ip",
        "ip",
        ip,
        reason,
    )
    db.commit()
    return jsonify({"ok": True}), 201


@app.delete("/api/admin/ip-bans/<int:ban_id>")
def admin_remove_ip_ban(ban_id: int) -> Any:
    admin_user, error = _admin_required_json()
    if error is not None:
        return error

    db = _db()
    row = db.execute("SELECT id, ip FROM ip_bans WHERE id = ?", (ban_id,)).fetchone()
    if row is None:
        return jsonify({"error": "IP-бан не найден"}), 404

    db.execute("DELETE FROM ip_bans WHERE id = ?", (ban_id,))
    _log_admin_action(
        db,
        int(admin_user["id"]),
        "unban_ip",
        "ip",
        row["ip"],
        f"Удален бан id={ban_id}",
    )
    db.commit()
    return jsonify({"ok": True})


@sock.route("/ws/call")
def ws_call(ws: Any) -> None:
    user_id = _require_user_id()
    if user_id is None:
        ws.send(json.dumps({"event": "call_error", "message": "Требуется вход"}, ensure_ascii=False))
        ws.close()
        return

    user = _user_by_id(user_id)
    if user is None or int(user["is_banned"]) == 1:
        ws.send(json.dumps({"event": "call_error", "message": "Доступ запрещен"}, ensure_ascii=False))
        ws.close()
        return

    client_id = uuid.uuid4().hex
    with CALL_LOCK:
        CALL_CLIENTS[client_id] = ws
    _ws_send(client_id, {"event": "ws_ready", "client_id": client_id})

    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break

            try:
                data = json.loads(raw)
            except Exception:
                _ws_send(client_id, {"event": "call_error", "message": "Некорректный JSON"})
                continue

            event = str(data.get("event", "")).strip()

            if event == "call_join":
                channel_id = str(data.get("channel_id", "")).strip()
                mode = str(data.get("mode", "audio")).strip().lower()
                mode = "video" if mode == "video" else "audio"

                if not channel_id:
                    _ws_send(client_id, {"event": "call_error", "message": "Канал не указан"})
                    continue
                if not _can_join_call(channel_id, user_id):
                    _ws_send(client_id, {"event": "call_error", "message": "Нет доступа к звонку в этом канале"})
                    continue
                room_channel = _channel_by_slug(channel_id)
                room_name = room_channel["name"] if room_channel is not None else channel_id

                _leave_call(client_id, notify=True)
                room = f"call:{channel_id}"

                participant = {
                    "client_id": client_id,
                    "user_id": int(user["id"]),
                    "name": user["name"],
                    "username": user["username"],
                    "avatar_url": user["avatar_url"],
                    "mode": mode,
                }

                with CALL_LOCK:
                    others = [value for cid, value in CALL_PARTICIPANTS[room].items() if cid != client_id]
                    CALL_PARTICIPANTS[room][client_id] = participant
                    CLIENT_ROOM[client_id] = room

                _ws_send(
                    client_id,
                    {
                        "event": "call_joined",
                        "room": room,
                        "self_client_id": client_id,
                        "participants": others,
                    },
                )
                _ws_broadcast(room, {"event": "call_participant_joined", **participant}, exclude=client_id)
                _broadcast_state_changed(
                    "call_started",
                    channel_id,
                    title=f"{user['name']} звонит",
                    body=f"Звонок в {room_name}",
                )
                continue

            if event == "call_leave":
                _leave_call(client_id, notify=True)
                continue

            if event == "call_signal":
                to_client = str(data.get("to", "")).strip()
                signal = data.get("signal")
                if not to_client or signal is None:
                    continue

                with CALL_LOCK:
                    from_room = CLIENT_ROOM.get(client_id)
                    to_room = CLIENT_ROOM.get(to_client)
                if from_room is None or to_room is None or from_room != to_room:
                    continue

                _ws_send(to_client, {"event": "call_signal", "from": client_id, "signal": signal})
                continue

            if event == "ping":
                _ws_send(client_id, {"event": "pong"})
                continue
    finally:
        _leave_call(client_id, notify=True)
        with CALL_LOCK:
            CALL_CLIENTS.pop(client_id, None)


if __name__ == "__main__":
    app.run(debug=True)
