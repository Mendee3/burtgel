#!/usr/bin/env python3
import cgi
import csv
import datetime as dt
import hashlib
import mimetypes
import hmac
import html
import io
import os
import secrets
import sqlite3
import ssl
import struct
import subprocess
import sys
import textwrap
import zlib
from zoneinfo import ZoneInfo
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote
from wsgiref.simple_server import make_server
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
DOCS_DIR = DATA_DIR
DB_PATH = Path(os.environ.get("BURTGEL_DB_PATH", DATA_DIR / "burtgel.db"))
IMPORT_DIR = Path(os.environ.get("BURTGEL_IMPORT_DIR", BASE_DIR / "extracted"))
HOST = os.environ.get("BURTGEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("BURTGEL_PORT", "8443"))
SSL_CERT = Path(os.environ.get("BURTGEL_CERT_FILE", DATA_DIR / "ssl" / "cert.pem"))
SSL_KEY = Path(os.environ.get("BURTGEL_KEY_FILE", DATA_DIR / "ssl" / "key.pem"))
SESSION_COOKIE = "burtgel_session"
SECRET_KEY = os.environ.get("BURTGEL_SECRET_KEY", "change-me-before-production")
PASSWORD_MIN_LENGTH = 12
PASSWORD_POLICY_TEXT = (
    "Шинэ нууц үг дараах шаардлагыг заавал хангасан байна: хамгийн багадаа 12 тэмдэгт, "
    "дор хаяж 1 том үсэг, 1 жижиг үсэг, 1 тоо, 1 тусгай тэмдэгттэй, зай агуулаагүй байна."
)
REVIEW_INTERVAL_DAYS = 365
FREQUENCY_OPTIONS = ["Сараар", "Улирлаар", "Хагас жилээр", "Жилээр"]
FREQUENCY_DAYS = {"Сараар": 30, "Улирлаар": 90, "Хагас жилээр": 180, "Жилээр": 365}
REVIEW_TIMER_KEY = "asset_review_deadline"
LOGO_ASSET_URL = "/static/dico_logo.png?v=20260330-dc-logo"
PDF_FONT_PATH = Path("/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf")

ASSET_FIELDS = [
    ("asset_name", "Хөрөнгийн нэр", True),
    ("description", "Хөрөнгийн тодорхойлолт", True),
    ("asset_type", "Хөрөнгийн төрөл", True),
    ("asset_group_code", "Хөрөнгийн бүлэг / код", True),
    ("has_personal_data", "Хувь хүний мэдээлэл байгаа эсэх", True),
    ("has_sensitive_data", "Эмзэг мэдээлэл байгаа эсэх", True),
    ("owner", "Хөрөнгө эзэмшигч", True),
    ("custodian", "Хөрөнгийн хариуцагч", True),
    ("location", "Байршил", True),
    ("access_right", "Хандах эрх", False),
    ("retention_period", "Хадгалах хугацаа", False),
    ("confidentiality", "Нууцлал", False),
    ("integrity_impact", "Бүрэн бүтэн байдалд нөлөөлөл", False),
    ("availability_impact", "Хүртээмжтэй байдалд нөлөөлөл", False),
    ("asset_value", "Хөрөнгийн үнэ цэн", False),
    ("asset_category", "Хөрөнгийн ангилал", False),
]
LIST_FIELDS = [
    ("asset_name", "Хөрөнгө"),
    ("asset_type", "Төрөл"),
    ("asset_group_code", "Бүлэг / Код"),
    ("owner", "Эзэмшигч"),
    ("asset_category", "Ангилал"),
    ("updated_at", "Сүүлд өөрчилсөн"),
]
ATTACHMENT_REGISTERS = [
    {
        "slug": "ustgalyn-burtgel",
        "table": "attachment_disposals",
        "entity_type": "attachment_disposal",
        "title": "Хавсралт 2. Мэдээллийн хөрөнгийн устгалын бүртгэл",
        "description": "Админ энэ бүртгэлийг систем дээрээс мөрөөр нь хөтөлнө.",
        "fields": [
            ("disposal_date", "Устгалын огноо", True, "text"),
            ("asset_name", "Устгасан мэдээлэл / хөрөнгийн нэр", True, "text"),
            ("information_classification", "Мэдээллийн ангилал", True, "text"),
            ("location_system", "Байршил / Систем", True, "text"),
            ("disposal_method", "Устгалын арга", True, "text"),
            ("disposal_basis", "Устгалын үндэслэл", True, "textarea"),
            ("executor_name", "Гүйцэтгэгч", True, "text"),
            ("approved_by", "Зөвшөөрсөн", True, "text"),
            ("act_number", "Актын №", False, "text"),
            ("notes", "Тайлбар", False, "textarea"),
        ],
        "list_fields": [
            ("disposal_date", "Устгалын огноо"),
            ("asset_name", "Хөрөнгийн нэр"),
            ("information_classification", "Ангилал"),
            ("location_system", "Байршил / Систем"),
            ("approved_by", "Зөвшөөрсөн"),
            ("updated_at", "Сүүлд өөрчилсөн"),
        ],
    },
    {
        "slug": "uurchlultiin-negdsen-burtgel",
        "table": "attachment_changes",
        "entity_type": "attachment_change",
        "title": "Хавсралт 3. Өөрчлөлтийн нэгдсэн бүртгэл",
        "description": "Админ өөрчлөлтийн хүсэлт, шийдвэрлэл, хэрэгжилтийн мэдээллийг энд бүртгэнэ.",
        "fields": [
            ("request_number", "Хүсэлтийн дугаар", True, "text"),
            ("request_type", "Хүсэлтийн төрөл", True, "text"),
            ("change_summary", "Өөрчлөлтийн товч агуулга", True, "textarea"),
            ("request_date", "Хүсэлт гаргасан огноо", True, "text"),
            ("requester_name", "Хүсэлт гаргагч", True, "text"),
            ("related_asset_number", "Хамаарах хөрөнгийн дугаар", False, "text"),
            ("status", "Төлөв", True, "text"),
            ("priority", "Эрэмбэ", False, "text"),
            ("planned_implementation_date", "Шийдэл хэрэгжүүлэх хугацаа", False, "text"),
            ("actual_implementation_date", "Бодит хэрэгжүүлсэн хугацаа", False, "text"),
            ("decision", "Шийдвэр", False, "textarea"),
            ("decision_reason", "Шалтгаан", False, "textarea"),
            ("decision_date", "Шийдвэр гаргасан огноо", False, "text"),
            ("decision_unit", "Шийдвэр гаргасан нэгж", False, "text"),
            ("change_implemented_date", "Өөрчлөлт хэрэгжүүлсэн огноо", False, "text"),
            ("change_verified_date", "Өөрчлөлтийг магадласан огноо", False, "text"),
        ],
        "list_fields": [
            ("request_number", "Хүсэлтийн дугаар"),
            ("request_type", "Төрөл"),
            ("request_date", "Хүсэлтийн огноо"),
            ("requester_name", "Хүсэлт гаргагч"),
            ("status", "Төлөв"),
            ("updated_at", "Сүүлд өөрчилсөн"),
        ],
    },
]
DEFAULT_ADMIN_DOCUMENT_CATEGORIES = [
    "Бодлого журам",
    "Бусад батлагдсан баримт бичиг",
    "Баримт бичгийн загвар",
]
DEFAULT_USERS = [
    ("fra_user", "", "fra", 0),
    ("legal_user", "", "legal", 0),
    ("md_user", "", "md", 0),
    ("stg_user", "", "stg", 0),
]
CSV_IMPORT_FILE = DATA_DIR / "INFORMATION ASSET REGISTER MERGED 2025.csv"
DEPARTMENT_SPECS = [
    {
        "sources": ["Стратегийн хэлтэс"],
        "code": "STG",
        "slug": "stg",
        "name": "Стратегийн хэлтэс",
        "user": ("stg_user", "stg123"),
    },
    {
        "sources": ["Дотоод аудитын хэлтэс"],
        "code": "AUDIT",
        "slug": "audit",
        "name": "Дотоод аудитын хэлтэс",
        "user": ("audit_user", "audit123"),
    },
    {
        "sources": ["Санхүүгийн хэлтэс"],
        "code": "FIN",
        "slug": "finance",
        "name": "Санхүүгийн хэлтэс",
        "user": ("finance_user", "finance123"),
    },
    {
        "sources": ["Төлөвлөлтийн хэлтэс"],
        "code": "PLAN",
        "slug": "planning",
        "name": "Төлөвлөлтийн хэлтэс",
        "user": ("planning_user", "planning123"),
    },
    {
        "sources": ["Франчайзийн хэлтэс"],
        "code": "FRA",
        "slug": "fra",
        "name": "Франчайзийн хэлтэс",
        "user": ("fra_user", "fra123"),
    },
    {
        "sources": ["Хуулийн хэлтэс"],
        "code": "LEGAL",
        "slug": "legal",
        "name": "Хуулийн хэлтэс",
        "user": ("legal_user", "legal123"),
    },
    {
        "sources": ["Мерчиндайзингийн хэлтэс"],
        "code": "MD",
        "slug": "md",
        "name": "Мерчиндайзингийн хэлтэс",
        "user": ("md_user", "md123"),
    },
    {
        "sources": ["Ханган нийлүүлэлтийн хэлтэс"],
        "code": "SCM",
        "slug": "scm",
        "name": "Ханган нийлүүлэлтийн хэлтэс",
        "user": ("scm_user", "scm123"),
    },
    {
        "sources": ["Хүний нөөцийн хэлтэс"],
        "code": "HR",
        "slug": "hr",
        "name": "Хүний нөөцийн хэлтэс",
        "user": ("hr_user", "hr123"),
    },
    {
        "sources": [
            "Дэлгүүр хөгжүүлэлт /SD/ - Дэлгүүр төлөвлөлт",
            "Дэлгүүр хөгжүүлэлт /Facility/ - Дэлгүүр төлөвлөлт",
        ],
        "code": "STORE-PLAN",
        "slug": "store-planning",
        "name": "Дэлгүүр төлөвлөлт",
        "user": ("store_planning_user", "storeplanning123"),
    },
    {
        "sources": [
            "Дэлгүүр хөгжүүлэлт /REM/",
            "Дэлгүүр хөгжүүлэлт /Maintenance/",
            "Дэлгүүр хөгжүүлэлт /Set-Up/",
        ],
        "code": "STORE-DEV",
        "slug": "store-development",
        "name": "Дэлгүүр хөгжүүлэлт",
        "user": ("store_development_user", "storedevelopment123"),
    },
    {
        "sources": ["Чанар, ХАБ-ын хэлтэс"],
        "code": "QHSE",
        "slug": "qhse",
        "name": "Чанар, ХАБ-ын хэлтэс",
        "user": ("qhse_user", "qhse123"),
    },
    {
        "sources": ["Маркетингийн хэлтэс"],
        "code": "MKT",
        "slug": "marketing",
        "name": "Маркетингийн хэлтэс",
        "user": ("marketing_user", "marketing123"),
    },
    {
        "sources": ["Мэдээллийн технологийн хэлтэс"],
        "code": "IT",
        "slug": "it",
        "name": "Мэдээллийн технологийн хэлтэс",
        "user": ("it_user", "it123"),
    },
]
XML_NS = {
    "a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "pkg": "http://schemas.openxmlformats.org/package/2006/relationships",
}


def slugify(value):
    cleaned = []
    for char in value.lower():
        if char.isalnum():
            cleaned.append(char)
        elif cleaned and cleaned[-1] != "-":
            cleaned.append("-")
    return "".join(cleaned).strip("-") or "department"


def normalize_text(value):
    if value is None:
        return ""
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()


def normalize_flag(value):
    text = normalize_text(value).upper()
    if text in {"Y", "YES"}:
        return "Y"
    if text in {"N", "NO"}:
        return "N"
    return text


SOURCE_DEPARTMENT_MAP = {
    source_name: spec for spec in DEPARTMENT_SPECS for source_name in spec["sources"]
}


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"{salt}${digest.hex()}"


def verify_password(password, stored_value):
    if not stored_value:
        return False
    try:
        salt, expected = stored_value.split("$", 1)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return hmac.compare_digest(actual, expected)


def validate_password_policy(password):
    errors = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"хамгийн багадаа {PASSWORD_MIN_LENGTH} тэмдэгт")
    if any(char.isspace() for char in password):
        errors.append("зайгүй")
    if not any(char.islower() for char in password):
        errors.append("дор хаяж нэг жижиг үсэг")
    if not any(char.isupper() for char in password):
        errors.append("дор хаяж нэг том үсэг")
    if not any(char.isdigit() for char in password):
        errors.append("дор хаяж нэг тоо")
    if not any(not char.isalnum() for char in password):
        errors.append("дор хаяж нэг тусгай тэмдэгт")
    if errors:
        return "Нууц үгийн шаардлага хангаагүй байна: " + ", ".join(errors) + "."
    return ""


def generate_temporary_password(length=16):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+?"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if not validate_password_policy(password):
            return password


_TZ = ZoneInfo("Asia/Ulaanbaatar")


def now_utc():
    return dt.datetime.now(_TZ).replace(microsecond=0)


def _parse_dt(value):
    """Parse an ISO datetime string; treat naive values as UTC (legacy records)."""
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def fmt_notice(message):
    if not message:
        return ""
    return f'<div class="notice">{html.escape(message)}</div>'


def fmt_error(message):
    if not message:
        return ""
    return f'<div class="error">{html.escape(message)}</div>'


def qs_value(params, key, default=""):
    values = params.get(key)
    if not values:
        return default
    return values[0]


def get_setting(conn, key, default=""):
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn, key, value):
    conn.execute(
        """
        INSERT INTO app_settings(key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, value, now_utc().isoformat()),
    )


def get_review_deadline(conn):
    value = get_setting(conn, REVIEW_TIMER_KEY)
    if value:
        try:
            return _parse_dt(value)
        except ValueError:
            pass
    deadline = now_utc() + dt.timedelta(days=REVIEW_INTERVAL_DAYS)
    set_setting(conn, REVIEW_TIMER_KEY, deadline.isoformat())
    conn.commit()
    return deadline


def format_review_countdown(deadline):
    remaining = deadline - now_utc()
    if remaining.total_seconds() <= 0:
        return "Хугацаа дууссан"
    total_seconds = int(remaining.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    return f"{days} өдөр {hours} цаг {minutes} минут"


def format_time_left(frequency, base_date_str):
    days = FREQUENCY_DAYS.get(frequency)
    if not days or not base_date_str:
        return "—"
    try:
        base = _parse_dt(base_date_str)
    except (ValueError, TypeError):
        return "—"
    deadline = base + dt.timedelta(days=days)
    remaining = (deadline - now_utc()).days
    if remaining < 0:
        return f'<span class="timeleft-over">Хугацаа хэтэрсэн ({abs(remaining)} өдөр)</span>'
    if remaining == 0:
        return '<span class="timeleft-due">Өнөөдөр дуусна</span>'
    return f'<span class="timeleft-ok">{remaining} өдөр</span>'


def format_days_until(due_date_str):
    if not due_date_str:
        return "—"
    try:
        due = dt.date.fromisoformat(due_date_str)
    except (ValueError, TypeError):
        return "—"
    today = now_utc().date()
    remaining = (due - today).days
    if remaining < 0:
        return f'<span class="timeleft-over">Хугацаа хэтэрсэн ({abs(remaining)} өдөр)</span>'
    if remaining == 0:
        return '<span class="timeleft-due">Өнөөдөр дуусна</span>'
    return f'<span class="timeleft-ok">{remaining} өдөр</span>'


def parse_post(environ):
    try:
        size = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        size = 0
    raw = environ["wsgi.input"].read(size).decode("utf-8")
    return {key: values[0] if values else "" for key, values in parse_qs(raw, keep_blank_values=True).items()}


def parse_multipart(environ):
    env = {
        "REQUEST_METHOD": environ.get("REQUEST_METHOD", "POST"),
        "CONTENT_TYPE": environ.get("CONTENT_TYPE", ""),
        "CONTENT_LENGTH": environ.get("CONTENT_LENGTH", "0"),
    }
    return cgi.FieldStorage(fp=environ["wsgi.input"], environ=env, keep_blank_values=True)


def response(start_response, status, body, headers=None):
    payload = body.encode("utf-8")
    final_headers = [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(payload)))]
    if headers:
        final_headers.extend(headers)
    start_response(status, final_headers)
    return [payload]


def redirect(start_response, location, headers=None):
    final_headers = [("Location", location)]
    if headers:
        final_headers.extend(headers)
    start_response("302 Found", final_headers)
    return [b""]


def format_dt(value):
    if not value:
        return "-"
    try:
        return _parse_dt(value).astimezone(_TZ).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return html.escape(str(value))


def format_multiline(value):
    return html.escape(normalize_text(value) or "-").replace("\n", "<br>")


def get_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def table_columns(conn, table_name):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})")}


def ensure_column(conn, table_name, column_name, definition):
    if column_name not in table_columns(conn, table_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def create_schema(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL DEFAULT '',
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            password_changed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
            asset_name TEXT NOT NULL,
            description TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            asset_group_code TEXT NOT NULL,
            has_personal_data TEXT NOT NULL,
            has_sensitive_data TEXT NOT NULL,
            owner TEXT NOT NULL,
            custodian TEXT NOT NULL,
            location TEXT NOT NULL,
            access_right TEXT NOT NULL DEFAULT '',
            retention_period TEXT NOT NULL DEFAULT '',
            confidentiality TEXT NOT NULL DEFAULT '',
            integrity_impact TEXT NOT NULL DEFAULT '',
            availability_impact TEXT NOT NULL DEFAULT '',
            asset_value TEXT NOT NULL DEFAULT '',
            asset_category TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS department_column_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
            field_name TEXT NOT NULL,
            can_edit INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(department_id, field_name)
        );

        CREATE TABLE IF NOT EXISTS user_department_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
            can_read INTEGER NOT NULL DEFAULT 0,
            can_update INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, department_id)
        );

        CREATE TABLE IF NOT EXISTS kpi_directories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS kpi_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            directory_id INTEGER NOT NULL REFERENCES kpi_directories(id) ON DELETE CASCADE,
            order_num INTEGER NOT NULL DEFAULT 0,
            indicator TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            formula TEXT NOT NULL DEFAULT '',
            target_level TEXT NOT NULL DEFAULT '',
            frequency TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attachment_disposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            disposal_date TEXT NOT NULL DEFAULT '',
            asset_name TEXT NOT NULL DEFAULT '',
            information_classification TEXT NOT NULL DEFAULT '',
            location_system TEXT NOT NULL DEFAULT '',
            disposal_method TEXT NOT NULL DEFAULT '',
            disposal_basis TEXT NOT NULL DEFAULT '',
            executor_name TEXT NOT NULL DEFAULT '',
            approved_by TEXT NOT NULL DEFAULT '',
            act_number TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attachment_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_number TEXT NOT NULL DEFAULT '',
            request_type TEXT NOT NULL DEFAULT '',
            change_summary TEXT NOT NULL DEFAULT '',
            request_date TEXT NOT NULL DEFAULT '',
            requester_name TEXT NOT NULL DEFAULT '',
            related_asset_number TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            priority TEXT NOT NULL DEFAULT '',
            planned_implementation_date TEXT NOT NULL DEFAULT '',
            actual_implementation_date TEXT NOT NULL DEFAULT '',
            decision TEXT NOT NULL DEFAULT '',
            decision_reason TEXT NOT NULL DEFAULT '',
            decision_date TEXT NOT NULL DEFAULT '',
            decision_unit TEXT NOT NULL DEFAULT '',
            change_implemented_date TEXT NOT NULL DEFAULT '',
            change_verified_date TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS custom_registers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS custom_register_columns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            register_id INTEGER NOT NULL REFERENCES custom_registers(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            slug TEXT NOT NULL,
            display_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(register_id, slug)
        );

        CREATE TABLE IF NOT EXISTS custom_register_rows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            register_id INTEGER NOT NULL REFERENCES custom_registers(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS custom_register_cells (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            row_id INTEGER NOT NULL REFERENCES custom_register_rows(id) ON DELETE CASCADE,
            column_id INTEGER NOT NULL REFERENCES custom_register_columns(id) ON DELETE CASCADE,
            value TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(row_id, column_id)
        );

        CREATE TABLE IF NOT EXISTS admin_document_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL UNIQUE,
            display_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admin_document_category_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL UNIQUE,
            category_id INTEGER REFERENCES admin_document_categories(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    ensure_column(conn, "users", "last_login_at", "TEXT")
    ensure_column(conn, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "password_changed_at", "TEXT")
    conn.commit()


def parse_shared_strings(zf):
    try:
        root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    except KeyError:
        return []
    items = []
    for node in root.findall("a:si", XML_NS):
        items.append("".join((text.text or "") for text in node.iterfind(".//a:t", XML_NS)))
    return items


def first_sheet_target(zf):
    workbook = ET.fromstring(zf.read("xl/workbook.xml"))
    first_sheet = workbook.find("a:sheets/a:sheet", XML_NS)
    rel_id = first_sheet.attrib["{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"]
    relations = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    for relation in relations.findall("pkg:Relationship", XML_NS):
        if relation.attrib["Id"] == rel_id:
            return "xl/" + relation.attrib["Target"]
    raise RuntimeError("Workbook does not contain a resolvable sheet target")


def cell_value(cell, shared_strings):
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return "".join((text.text or "") for text in cell.iterfind(".//a:t", XML_NS))
    value = cell.find("a:v", XML_NS)
    if value is None:
        return None
    if cell_type == "s":
        return shared_strings[int(value.text)]
    return value.text


def read_xlsx_rows(path):
    with ZipFile(path) as zf:
        shared_strings = parse_shared_strings(zf)
        sheet = ET.fromstring(zf.read(first_sheet_target(zf)))
        for row in sheet.findall(".//a:sheetData/a:row", XML_NS):
            values = {}
            for cell in row.findall("a:c", XML_NS):
                ref = cell.attrib.get("r", "")
                letters = "".join(char for char in ref if char.isalpha())
                values[letters] = cell_value(cell, shared_strings)
            yield values


def read_csv_assets(path):
    current_department = ""
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        for row_index, row in enumerate(reader, start=1):
            if row_index < 4:
                continue
            department_name = normalize_text(row[1] if len(row) > 1 else "")
            if department_name:
                current_department = department_name
            asset_name = normalize_text(row[2] if len(row) > 2 else "")
            if not current_department or not asset_name:
                continue
            yield {
                "source_department": current_department,
                "asset_name": asset_name,
                "description": normalize_text(row[3] if len(row) > 3 else ""),
                "asset_type": normalize_text(row[4] if len(row) > 4 else ""),
                "asset_group_code": normalize_text(row[5] if len(row) > 5 else ""),
                "has_personal_data": normalize_flag(row[6] if len(row) > 6 else ""),
                "has_sensitive_data": normalize_flag(row[7] if len(row) > 7 else ""),
                "owner": normalize_text(row[8] if len(row) > 8 else ""),
                "custodian": normalize_text(row[9] if len(row) > 9 else ""),
                "location": normalize_text(row[10] if len(row) > 10 else ""),
                "access_right": "",
                "retention_period": normalize_text(row[11] if len(row) > 11 else ""),
                "confidentiality": normalize_text(row[12] if len(row) > 12 else ""),
                "integrity_impact": normalize_text(row[13] if len(row) > 13 else ""),
                "availability_impact": normalize_text(row[14] if len(row) > 14 else ""),
                "asset_value": normalize_text(row[15] if len(row) > 15 else ""),
                "asset_category": normalize_text(row[16] if len(row) > 16 else ""),
            }


def import_assets(conn):
    asset_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    if asset_count or not IMPORT_DIR.exists():
        return
    for workbook in sorted(IMPORT_DIR.glob("*.xlsx")):
        rows = list(read_xlsx_rows(workbook))
        if len(rows) < 4:
            continue
        dept_code = slugify(workbook.stem.split()[0])
        dept_name = normalize_text(rows[3].get("A")) or workbook.stem
        conn.execute(
            "INSERT OR IGNORE INTO departments(code, slug, name) VALUES (?, ?, ?)",
            (dept_code.upper(), dept_code, dept_name),
        )
        department_id = conn.execute("SELECT id FROM departments WHERE slug = ?", (dept_code,)).fetchone()["id"]
        for row in rows[3:]:
            asset_name = normalize_text(row.get("B"))
            if not asset_name:
                continue
            payload = {
                "department_id": department_id,
                "asset_name": asset_name,
                "description": normalize_text(row.get("C")),
                "asset_type": normalize_text(row.get("D")),
                "asset_group_code": normalize_text(row.get("E")),
                "has_personal_data": normalize_flag(row.get("F")),
                "has_sensitive_data": normalize_flag(row.get("G")),
                "owner": normalize_text(row.get("H")),
                "custodian": normalize_text(row.get("I")),
                "location": normalize_text(row.get("J")),
                "access_right": normalize_text(row.get("K")),
                "retention_period": normalize_text(row.get("L")),
                "confidentiality": normalize_text(row.get("M")),
                "integrity_impact": normalize_text(row.get("N")),
                "availability_impact": normalize_text(row.get("O")),
                "asset_value": normalize_text(row.get("P")),
                "asset_category": normalize_text(row.get("Q")),
            }
            timestamp = now_utc().isoformat()
            conn.execute(
                """
                INSERT INTO assets (
                    department_id, asset_name, description, asset_type, asset_group_code,
                    has_personal_data, has_sensitive_data, owner, custodian, location,
                    access_right, retention_period, confidentiality, integrity_impact,
                    availability_impact, asset_value, asset_category, created_at, updated_at
                )
                VALUES (
                    :department_id, :asset_name, :description, :asset_type, :asset_group_code,
                    :has_personal_data, :has_sensitive_data, :owner, :custodian, :location,
                    :access_right, :retention_period, :confidentiality, :integrity_impact,
                    :availability_impact, :asset_value, :asset_category, :created_at, :updated_at
                )
                """,
                {**payload, "created_at": timestamp, "updated_at": timestamp},
            )
    conn.commit()


def seed_users(conn):
    department_lookup = {row["slug"]: row["id"] for row in conn.execute("SELECT id, slug FROM departments")}
    existing = {row["username"] for row in conn.execute("SELECT username FROM users")}

    # Seed admin account on first initialisation — no hardcoded password.
    if "admin" not in existing:
        tmp_password = secrets.token_urlsafe(16)
        conn.execute(
            """
            INSERT INTO users(username, password_hash, department_id, is_admin, created_at, must_change_password, password_changed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "admin",
                hash_password(tmp_password),
                None,
                1,
                now_utc().isoformat(),
                1,
                None,
            ),
        )
        print("=" * 60)
        print("ADMIN ACCOUNT CREATED — FIRST-RUN TEMPORARY PASSWORD:")
        print(f"  Username : admin")
        print(f"  Password : {tmp_password}")
        print("  You will be forced to change it on first login.")
        print("=" * 60)

    for username, password, dept_slug, is_admin in DEFAULT_USERS:
        if username in existing:
            continue
        department_id = department_lookup.get(dept_slug) if dept_slug else None
        conn.execute(
            """
            INSERT INTO users(username, password_hash, department_id, is_admin, created_at, must_change_password, password_changed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                hash_password(password) if password else "",
                department_id,
                is_admin,
                now_utc().isoformat(),
                0,
                now_utc().isoformat() if password else None,
            ),
        )
    conn.commit()


def ensure_department(conn, spec):
    conn.execute(
        """
        INSERT INTO departments(code, slug, name)
        VALUES (?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
            code = excluded.code,
            name = excluded.name
        """,
        (spec["code"], spec["slug"], spec["name"]),
    )
    return conn.execute("SELECT id FROM departments WHERE slug = ?", (spec["slug"],)).fetchone()["id"]


def ensure_department_user(conn, spec, department_id):
    username, _ = spec["user"]
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE users SET department_id = ?, is_admin = 0, is_active = 1 WHERE id = ?",
            (department_id, existing["id"]),
        )
        return
    conn.execute(
        """
        INSERT INTO users(username, password_hash, department_id, is_admin, created_at, must_change_password)
        VALUES (?, ?, ?, 0, ?, 0)
        """,
        (username, "", department_id, now_utc().isoformat()),
    )
def sync_assets_from_csv(conn, csv_path=CSV_IMPORT_FILE):
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV import file not found: {csv_path}")

    rows = list(read_csv_assets(csv_path))
    if not rows:
        raise RuntimeError(f"CSV import file does not contain importable assets: {csv_path}")

    unknown_departments = sorted({row["source_department"] for row in rows if row["source_department"] not in SOURCE_DEPARTMENT_MAP})
    if unknown_departments:
        raise RuntimeError("Unknown source departments in CSV: " + ", ".join(unknown_departments))

    timestamp = now_utc().isoformat()
    department_ids = {}
    for spec in DEPARTMENT_SPECS:
        department_id = ensure_department(conn, spec)
        department_ids[spec["slug"]] = department_id
        ensure_department_user(conn, spec, department_id)

    conn.execute("DELETE FROM assets")
    for row in rows:
        spec = SOURCE_DEPARTMENT_MAP[row["source_department"]]
        conn.execute(
            """
            INSERT INTO assets (
                department_id, asset_name, description, asset_type, asset_group_code,
                has_personal_data, has_sensitive_data, owner, custodian, location,
                access_right, retention_period, confidentiality, integrity_impact,
                availability_impact, asset_value, asset_category, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                department_ids[spec["slug"]],
                row["asset_name"],
                row["description"],
                row["asset_type"],
                row["asset_group_code"],
                row["has_personal_data"],
                row["has_sensitive_data"],
                row["owner"],
                row["custodian"],
                row["location"],
                row["access_right"],
                row["retention_period"],
                row["confidentiality"],
                row["integrity_impact"],
                row["availability_impact"],
                row["asset_value"],
                row["asset_category"],
                timestamp,
                timestamp,
            ),
        )
    conn.commit()


def seed_permissions(conn):
    timestamp = now_utc().isoformat()
    departments = list(conn.execute("SELECT id FROM departments"))
    for department in departments:
        for field_name, _, _ in ASSET_FIELDS:
            conn.execute(
                """
                INSERT OR IGNORE INTO department_column_permissions(
                    department_id, field_name, can_edit, created_at, updated_at
                ) VALUES (?, ?, 1, ?, ?)
                """,
                (department["id"], field_name, timestamp, timestamp),
            )
    conn.commit()


def migrate_user_password_state(conn):
    conn.execute(
        """
        UPDATE users
        SET password_hash = '', must_change_password = 0
        WHERE is_admin = 0 AND password_changed_at IS NULL AND must_change_password = 0
        """
    )
    conn.execute(
        """
        UPDATE users
        SET password_changed_at = COALESCE(password_changed_at, created_at)
        WHERE is_admin = 1 AND password_hash != ''
        """
    )
    conn.commit()


def migrate_user_dept_perms(conn):
    """Seed user_department_permissions from users.department_id for existing users."""
    timestamp = now_utc().isoformat()
    for u in conn.execute("SELECT id, department_id FROM users WHERE is_admin = 0 AND department_id IS NOT NULL").fetchall():
        conn.execute(
            """INSERT OR IGNORE INTO user_department_permissions
               (user_id, department_id, can_read, can_update, created_at, updated_at)
               VALUES (?, ?, 1, 1, ?, ?)""",
            (u["id"], u["department_id"], timestamp, timestamp),
        )
    conn.commit()


def ensure_database():
    conn = get_db()
    create_schema(conn)
    import_assets(conn)
    seed_users(conn)
    seed_permissions(conn)
    migrate_user_password_state(conn)
    migrate_user_dept_perms(conn)
    ensure_column(conn, "assets", "review_frequency", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "kpi_items", "due_date", "TEXT NOT NULL DEFAULT ''")
    conn.commit()
    seed_custom_register_samples(conn)
    seed_admin_document_categories(conn)
    conn.commit()
    conn.close()


def sign_cookie(value):
    signature = hmac.new(SECRET_KEY.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{signature}"
def verify_signed_cookie(value):
    try:
        raw, signature = value.rsplit(".", 1)
    except ValueError:
        return None
    expected = hmac.new(SECRET_KEY.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(signature, expected):
        return raw
    return None


def session_cookie_header(session_id, expires_days=7):
    morsel = cookies.SimpleCookie()
    morsel[SESSION_COOKIE] = sign_cookie(session_id)
    morsel[SESSION_COOKIE]["path"] = "/"
    morsel[SESSION_COOKIE]["httponly"] = True
    morsel[SESSION_COOKIE]["samesite"] = "Lax"
    if expires_days <= 0:
        morsel[SESSION_COOKIE]["max-age"] = 0
    else:
        morsel[SESSION_COOKIE]["max-age"] = expires_days * 24 * 60 * 60
    return ("Set-Cookie", morsel.output(header="").strip())


def record_audit(conn, actor_user_id, action, entity_type, entity_id=None, department_id=None, details="", target_user_id=None):
    conn.execute(
        """
        INSERT INTO audit_logs(actor_user_id, target_user_id, department_id, action, entity_type, entity_id, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (actor_user_id, target_user_id, department_id, action, entity_type, str(entity_id or ""), details, now_utc().isoformat()),
    )


def get_current_user(environ, conn):
    raw_cookie = environ.get("HTTP_COOKIE", "")
    jar = cookies.SimpleCookie(raw_cookie)
    if SESSION_COOKIE not in jar:
        return None
    signed = jar[SESSION_COOKIE].value
    session_id = verify_signed_cookie(signed)
    if not session_id:
        return None
    session_row = conn.execute(
        """
        SELECT sessions.id AS session_id, sessions.expires_at, users.*, departments.slug AS department_slug, departments.name AS department_name
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        LEFT JOIN departments ON departments.id = users.department_id
        WHERE sessions.id = ? AND users.is_active = 1
        """,
        (session_id,),
    ).fetchone()
    if not session_row:
        return None
    if _parse_dt(session_row["expires_at"]) < now_utc():
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        return None
    return session_row


def create_session(conn, user_id):
    session_id = secrets.token_urlsafe(32)
    expires_at = (now_utc() + dt.timedelta(days=7)).isoformat()
    conn.execute("INSERT INTO sessions(id, user_id, expires_at) VALUES (?, ?, ?)", (session_id, user_id, expires_at))
    return session_id


def clear_session(conn, environ):
    raw_cookie = environ.get("HTTP_COOKIE", "")
    jar = cookies.SimpleCookie(raw_cookie)
    if SESSION_COOKIE in jar:
        signed = jar[SESSION_COOKIE].value
        session_id = verify_signed_cookie(signed)
        if session_id:
            conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))


def get_user_dept_perms(conn, user_id):
    """Return {department_id: {"can_read": bool, "can_update": bool}} for a user."""
    rows = conn.execute(
        "SELECT department_id, can_read, can_update FROM user_department_permissions WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    return {row["department_id"]: {"can_read": bool(row["can_read"]), "can_update": bool(row["can_update"])} for row in rows}


def save_user_dept_perms(conn, user_id, perms):
    """perms = {dept_id: {"can_read": bool, "can_update": bool}}. Replaces all existing rows."""
    timestamp = now_utc().isoformat()
    conn.execute("DELETE FROM user_department_permissions WHERE user_id = ?", (user_id,))
    for dept_id, p in perms.items():
        if p.get("can_read") or p.get("can_update"):
            conn.execute(
                """INSERT INTO user_department_permissions
                   (user_id, department_id, can_read, can_update, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, int(dept_id), int(bool(p.get("can_read"))), int(bool(p.get("can_update"))), timestamp, timestamp),
            )


def departments_for_user(conn, user):
    if user["is_admin"]:
        return list(conn.execute("SELECT * FROM departments ORDER BY name"))
    dept_ids = set()
    if user["department_id"]:
        dept_ids.add(user["department_id"])
    for row in conn.execute(
        "SELECT department_id FROM user_department_permissions WHERE user_id = ? AND can_read = 1", (user["id"],)
    ).fetchall():
        dept_ids.add(row["department_id"])
    if not dept_ids:
        return []
    placeholders = ",".join("?" * len(dept_ids))
    return list(conn.execute(f"SELECT * FROM departments WHERE id IN ({placeholders}) ORDER BY name", list(dept_ids)))


def can_access_department(user, department, conn=None):
    if not (user and department):
        return False
    if user["is_admin"]:
        return True
    if user["department_id"] == department["id"]:
        return True
    if conn is not None:
        row = conn.execute(
            "SELECT 1 FROM user_department_permissions WHERE user_id = ? AND department_id = ? AND can_read = 1",
            (user["id"], department["id"]),
        ).fetchone()
        return row is not None
    return False


def can_update_in_department(user, department, conn=None):
    if not (user and department):
        return False
    if user["is_admin"]:
        return True
    if conn is not None:
        row = conn.execute(
            "SELECT can_update FROM user_department_permissions WHERE user_id = ? AND department_id = ?",
            (user["id"], department["id"]),
        ).fetchone()
        if row is not None:
            return bool(row["can_update"])
    # fallback: primary department always has update
    return user["department_id"] == department["id"]


def can_edit_field(user, permissions, field_name):
    return bool(user and (user["is_admin"] or permissions.get(field_name, True)))

def password_setup_required(user):
    return bool(user and user["must_change_password"])


def get_department_permissions(conn, department_id):
    rows = conn.execute(
        "SELECT field_name, can_edit FROM department_column_permissions WHERE department_id = ?",
        (department_id,),
    ).fetchall()
    permissions = {row["field_name"]: bool(row["can_edit"]) for row in rows}
    for field_name, _, _ in ASSET_FIELDS:
        permissions.setdefault(field_name, True)
    return permissions


def get_attachment_register(slug):
    for register in ATTACHMENT_REGISTERS:
        if register["slug"] == slug:
            return register
    return None


def unique_slug(conn, table_name, base_value, ignore_id=None):
    base_slug = slugify(base_value or "register") or "register"
    candidate = base_slug
    counter = 2
    while True:
        if ignore_id is None:
            row = conn.execute(f"SELECT id FROM {table_name} WHERE slug = ?", (candidate,)).fetchone()
        else:
            row = conn.execute(f"SELECT id FROM {table_name} WHERE slug = ? AND id != ?", (candidate, ignore_id)).fetchone()
        if not row:
            return candidate
        candidate = f"{base_slug}-{counter}"
        counter += 1


def list_custom_registers(conn):
    return conn.execute(
        """
        SELECT custom_registers.*,
               COUNT(DISTINCT custom_register_columns.id) AS column_count,
               COUNT(DISTINCT custom_register_rows.id) AS row_count
        FROM custom_registers
        LEFT JOIN custom_register_columns ON custom_register_columns.register_id = custom_registers.id
        LEFT JOIN custom_register_rows ON custom_register_rows.register_id = custom_registers.id
        GROUP BY custom_registers.id
        ORDER BY custom_registers.updated_at DESC, custom_registers.title COLLATE NOCASE
        """
    ).fetchall()


def get_custom_register(conn, slug):
    candidate_values = {slug, unquote(slug)}
    for value in list(candidate_values):
        try:
            candidate_values.add(value.encode("latin-1").decode("utf-8"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    for candidate in candidate_values:
        row = conn.execute("SELECT * FROM custom_registers WHERE slug = ?", (candidate,)).fetchone()
        if row:
            return row
    return None


def list_custom_register_columns(conn, register_id):
    return conn.execute(
        "SELECT * FROM custom_register_columns WHERE register_id = ? ORDER BY display_order, id",
        (register_id,),
    ).fetchall()


def get_custom_register_row(conn, register_id, row_id):
    return conn.execute(
        "SELECT * FROM custom_register_rows WHERE register_id = ? AND id = ?",
        (register_id, row_id),
    ).fetchone()


def get_custom_register_grid(conn, register_id):
    columns = list_custom_register_columns(conn, register_id)
    rows = list(
        conn.execute(
            "SELECT * FROM custom_register_rows WHERE register_id = ? ORDER BY id DESC",
            (register_id,),
        )
    )
    if not rows:
        return columns, []
    values_by_row = {row["id"]: {} for row in rows}
    for cell in conn.execute(
        """
        SELECT custom_register_cells.row_id, custom_register_columns.slug, custom_register_cells.value
        FROM custom_register_cells
        JOIN custom_register_columns ON custom_register_columns.id = custom_register_cells.column_id
        WHERE custom_register_columns.register_id = ?
        """,
        (register_id,),
    ):
        values_by_row.setdefault(cell["row_id"], {})[cell["slug"]] = cell["value"]
    return columns, [{"row": row, "values": values_by_row.get(row["id"], {})} for row in rows]


def get_custom_row_values(conn, row_id):
    return {
        row["column_id"]: row["value"]
        for row in conn.execute(
            "SELECT column_id, value FROM custom_register_cells WHERE row_id = ?",
            (row_id,),
        )
    }


def create_custom_register(conn, title, description):
    title = normalize_text(title)
    if not title:
        return None, "Бүртгэлийн нэр оруулна уу."
    timestamp = now_utc().isoformat()
    slug = unique_slug(conn, "custom_registers", title)
    conn.execute(
        "INSERT INTO custom_registers(slug, title, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (slug, title, normalize_text(description), timestamp, timestamp),
    )
    return get_custom_register(conn, slug), ""


def rename_custom_register(conn, register, title):
    title = normalize_text(title)
    if not title:
        return "Бүртгэлийн нэр оруулна уу."
    existing = conn.execute(
        "SELECT id FROM custom_registers WHERE LOWER(title) = LOWER(?) AND id != ?",
        (title, register["id"]),
    ).fetchone()
    if existing:
        return "Ийм нэртэй бүртгэл аль хэдийн байна."
    conn.execute(
        "UPDATE custom_registers SET title = ?, slug = ?, updated_at = ? WHERE id = ?",
        (title, unique_slug(conn, "custom_registers", title, ignore_id=register["id"]), now_utc().isoformat(), register["id"]),
    )
    return ""


def seed_custom_register_samples(conn):
    existing = conn.execute("SELECT COUNT(*) FROM custom_registers").fetchone()[0]
    if existing:
        return
    create_custom_register(
        conn,
        "Жишиг бүртгэл",
        "Энэ нь админ шинэ багана үүсгэж, өгөгдөл оруулах жишиг бүртгэл юм.",
    )


def create_custom_register_column(conn, register, name):
    label = normalize_text(name)
    if not label:
        return None, "Баганын нэр оруулна уу."
    if len(label) > 80:
        return None, "Баганын нэр хэт урт байна."
    display_order = conn.execute(
        "SELECT COALESCE(MAX(display_order), 0) + 1 FROM custom_register_columns WHERE register_id = ?",
        (register["id"],),
    ).fetchone()[0]
    timestamp = now_utc().isoformat()
    conn.execute(
        "INSERT INTO custom_register_columns(register_id, name, slug, display_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (register["id"], label, unique_slug(conn, "custom_register_columns", label), display_order, timestamp, timestamp),
    )
    return conn.execute(
        "SELECT * FROM custom_register_columns WHERE register_id = ? ORDER BY id DESC LIMIT 1",
        (register["id"],),
    ).fetchone(), ""


def rename_custom_register_column(conn, register, column_id, name):
    label = normalize_text(name)
    if not label:
        return "Баганын нэр оруулна уу."
    if len(label) > 80:
        return "Баганын нэр хэт урт байна."
    column = conn.execute(
        "SELECT * FROM custom_register_columns WHERE id = ? AND register_id = ?",
        (column_id, register["id"]),
    ).fetchone()
    if not column:
        return "Багана олдсонгүй."
    conn.execute(
        "UPDATE custom_register_columns SET name = ?, updated_at = ? WHERE id = ?",
        (label, now_utc().isoformat(), column_id),
    )
    return ""


def save_custom_register_row(conn, register, values, row=None):
    timestamp = now_utc().isoformat()
    if row is None:
        conn.execute(
            "INSERT INTO custom_register_rows(register_id, created_at, updated_at) VALUES (?, ?, ?)",
            (register["id"], timestamp, timestamp),
        )
        row_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    else:
        row_id = row["id"]
        conn.execute("UPDATE custom_register_rows SET updated_at = ? WHERE id = ?", (timestamp, row_id))
    for column_id, value in values.items():
        conn.execute(
            """
            INSERT INTO custom_register_cells(row_id, column_id, value, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(row_id, column_id) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (row_id, column_id, normalize_text(value), timestamp, timestamp),
        )
    return row_id


def validate_custom_register_row_form(form, columns):
    return {column["id"]: normalize_text(form.get(f"column_{column['id']}", "")) for column in columns}


def custom_register_export_filename(register, extension):
    stem = slugify(register["title"]) or register["slug"] or "register"
    return f"{stem}.{extension}"


def xml_escape(value):
    return (
        normalize_text(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def excel_column_name(index):
    letters = []
    current = index
    while current >= 0:
        current, remainder = divmod(current, 26)
        letters.append(chr(65 + remainder))
        current -= 1
    return "".join(reversed(letters))


def build_xlsx_payload(title, matrix):
    rows_xml = []
    for row_index, row in enumerate(matrix, start=1):
        cells_xml = []
        for column_index, value in enumerate(row):
            ref = f"{excel_column_name(column_index)}{row_index}"
            cells_xml.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{xml_escape(value)}</t></is></c>')
        rows_xml.append(f'<row r="{row_index}">{"".join(cells_xml)}</row>')
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
        + ''.join(rows_xml) +
        '</sheetData></worksheet>'
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{xml_escape(title[:31] or "Sheet1")}" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '</Relationships>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        '</Relationships>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        '</Types>'
    )
    created = now_utc().isoformat() + "Z"
    core_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f'<dc:title>{xml_escape(title)}</dc:title><dc:creator>Burtgel</dc:creator><cp:lastModifiedBy>Burtgel</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified></cp:coreProperties>'
    )
    app_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>Burtgel</Application></Properties>'
    )
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as workbook:
        workbook.writestr("[Content_Types].xml", content_types)
        workbook.writestr("_rels/.rels", root_rels)
        workbook.writestr("docProps/core.xml", core_xml)
        workbook.writestr("docProps/app.xml", app_xml)
        workbook.writestr("xl/workbook.xml", workbook_xml)
        workbook.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        workbook.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buffer.getvalue()


def ttf_read_tables(font_bytes):
    num_tables = struct.unpack(">H", font_bytes[4:6])[0]
    tables = {}
    offset = 12
    for _ in range(num_tables):
        tag = font_bytes[offset:offset + 4].decode("ascii")
        _, table_offset, length = struct.unpack(">III", font_bytes[offset + 4:offset + 16])
        tables[tag] = (table_offset, length)
        offset += 16
    return tables


def ttf_parse_cmap(font_bytes, tables):
    cmap_offset, _ = tables["cmap"]
    num_tables = struct.unpack(">H", font_bytes[cmap_offset + 2:cmap_offset + 4])[0]
    chosen = None
    chosen_rank = -1
    for index in range(num_tables):
        record_offset = cmap_offset + 4 + index * 8
        platform_id, encoding_id, subtable_offset = struct.unpack(">HHI", font_bytes[record_offset:record_offset + 8])
        absolute = cmap_offset + subtable_offset
        format_type = struct.unpack(">H", font_bytes[absolute:absolute + 2])[0]
        rank = -1
        if platform_id == 3 and encoding_id == 10 and format_type == 12:
            rank = 4
        elif platform_id == 0 and format_type == 12:
            rank = 3
        elif platform_id == 3 and encoding_id in {1, 0} and format_type == 4:
            rank = 2
        elif platform_id == 0 and format_type == 4:
            rank = 1
        if rank > chosen_rank:
            chosen = (absolute, format_type)
            chosen_rank = rank
    if not chosen:
        return {}
    absolute, format_type = chosen
    mapping = {}
    if format_type == 12:
        groups = struct.unpack(">L", font_bytes[absolute + 12:absolute + 16])[0]
        pos = absolute + 16
        for _ in range(groups):
            start_char, end_char, start_glyph = struct.unpack(">LLL", font_bytes[pos:pos + 12])
            for codepoint in range(start_char, end_char + 1):
                mapping[codepoint] = start_glyph + (codepoint - start_char)
            pos += 12
        return mapping
    seg_count = struct.unpack(">H", font_bytes[absolute + 6:absolute + 8])[0] // 2
    end_codes_start = absolute + 14
    start_codes_start = end_codes_start + seg_count * 2 + 2
    id_delta_start = start_codes_start + seg_count * 2
    id_range_start = id_delta_start + seg_count * 2
    for index in range(seg_count):
        end_code = struct.unpack(">H", font_bytes[end_codes_start + index * 2:end_codes_start + index * 2 + 2])[0]
        start_code = struct.unpack(">H", font_bytes[start_codes_start + index * 2:start_codes_start + index * 2 + 2])[0]
        id_delta = struct.unpack(">h", font_bytes[id_delta_start + index * 2:id_delta_start + index * 2 + 2])[0]
        id_range_offset = struct.unpack(">H", font_bytes[id_range_start + index * 2:id_range_start + index * 2 + 2])[0]
        for codepoint in range(start_code, end_code + 1):
            if codepoint == 0xFFFF:
                continue
            if id_range_offset == 0:
                glyph_id = (codepoint + id_delta) & 0xFFFF
            else:
                glyph_offset = id_range_start + index * 2 + id_range_offset + (codepoint - start_code) * 2
                glyph_id = struct.unpack(">H", font_bytes[glyph_offset:glyph_offset + 2])[0] if glyph_offset + 2 <= len(font_bytes) else 0
                if glyph_id:
                    glyph_id = (glyph_id + id_delta) & 0xFFFF
            if glyph_id:
                mapping[codepoint] = glyph_id
    return mapping


def ttf_metrics(font_path):
    font_bytes = font_path.read_bytes()
    tables = ttf_read_tables(font_bytes)
    head_offset, _ = tables["head"]
    hhea_offset, _ = tables["hhea"]
    hmtx_offset, _ = tables["hmtx"]
    maxp_offset, _ = tables["maxp"]
    units_per_em = struct.unpack(">H", font_bytes[head_offset + 18:head_offset + 20])[0]
    x_min, y_min, x_max, y_max = struct.unpack(">hhhh", font_bytes[head_offset + 36:head_offset + 44])
    ascent = struct.unpack(">h", font_bytes[hhea_offset + 4:hhea_offset + 6])[0]
    descent = struct.unpack(">h", font_bytes[hhea_offset + 6:hhea_offset + 8])[0]
    number_of_hmetrics = struct.unpack(">H", font_bytes[hhea_offset + 34:hhea_offset + 36])[0]
    num_glyphs = struct.unpack(">H", font_bytes[maxp_offset + 4:maxp_offset + 6])[0]
    widths = []
    pos = hmtx_offset
    last_advance = 0
    for index in range(num_glyphs):
        if index < number_of_hmetrics:
            advance, _ = struct.unpack(">HH", font_bytes[pos:pos + 4])
            pos += 4
            last_advance = advance
        else:
            advance = last_advance
            pos += 2
        widths.append(advance)
    return {
        "font_bytes": font_bytes,
        "units_per_em": units_per_em,
        "bbox": (x_min, y_min, x_max, y_max),
        "ascent": ascent,
        "descent": descent,
        "widths": widths,
        "cmap": ttf_parse_cmap(font_bytes, tables),
    }


def pdf_hex_text(text):
    return text.encode("utf-16-be").hex().upper()


def build_pdf_payload(title, lines):
    font_metrics = ttf_metrics(PDF_FONT_PATH)
    cmap = font_metrics["cmap"]
    used_codepoints = sorted({ord(char) for line in lines for char in line if ord(char) <= 0xFFFF})
    cid_to_gid = bytearray((max(used_codepoints) + 1) * 2 if used_codepoints else 2)
    width_entries = []
    for codepoint in used_codepoints:
        glyph_id = cmap.get(codepoint, 0)
        cid_to_gid[codepoint * 2:codepoint * 2 + 2] = struct.pack(">H", glyph_id)
        width = 600
        if glyph_id and glyph_id < len(font_metrics["widths"]):
            width = int(font_metrics["widths"][glyph_id] * 1000 / font_metrics["units_per_em"])
        width_entries.append(f"{codepoint} [{width}]")
    to_unicode_lines = [
        "/CIDInit /ProcSet findresource begin",
        "12 dict begin",
        "begincmap",
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
        "/CMapName /BurtgelUnicode def",
        "/CMapType 2 def",
        "1 begincodespacerange",
        "<0000> <FFFF>",
        "endcodespacerange",
        f"{len(used_codepoints)} beginbfchar",
    ]
    for codepoint in used_codepoints:
        to_unicode_lines.append(f"<{codepoint:04X}> <{codepoint:04X}>")
    to_unicode_lines.extend(["endbfchar", "endcmap", "CMapName currentdict /CMap defineresource pop", "end", "end"])
    wrapped = []
    for line in lines:
        wrapped.extend(textwrap.wrap(line, width=84, replace_whitespace=False, drop_whitespace=False) or [""])
    page_chunks = [wrapped[index:index + 42] for index in range(0, len(wrapped), 42)] or [[""]]
    page_contents = []
    for chunk in page_chunks:
        commands = ["BT", "/F1 12 Tf", "40 795 Td"]
        first = True
        for line in chunk:
            if not first:
                commands.append("0 -17 Td")
            commands.append(f"<{pdf_hex_text(line)}> Tj")
            first = False
        commands.append("ET")
        page_contents.append("\n".join(commands).encode("utf-8"))
    objects = []
    def add_object(payload):
        objects.append(payload)
        return len(objects)
    pages_obj = add_object(b"")
    font_file_compressed = zlib.compress(font_metrics["font_bytes"])
    font_file_obj = add_object(f"<< /Length {len(font_file_compressed)} /Length1 {len(font_metrics['font_bytes'])} /Filter /FlateDecode >>\nstream\n".encode("ascii") + font_file_compressed + b"\nendstream")
    x_min, y_min, x_max, y_max = font_metrics["bbox"]
    descriptor_obj = add_object(("<< /Type /FontDescriptor /FontName /BurtgelFont /Flags 4 " f"/FontBBox [{x_min} {y_min} {x_max} {y_max}] /ItalicAngle 0 /Ascent {font_metrics['ascent']} /Descent {font_metrics['descent']} /CapHeight {font_metrics['ascent']} /StemV 80 /FontFile2 {font_file_obj} 0 R >>").encode("utf-8"))
    cid_to_gid_obj = add_object(f"<< /Length {len(cid_to_gid)} >>\nstream\n".encode("ascii") + bytes(cid_to_gid) + b"\nendstream")
    to_unicode_data = "\n".join(to_unicode_lines).encode("utf-8")
    to_unicode_obj = add_object(f"<< /Length {len(to_unicode_data)} >>\nstream\n".encode("ascii") + to_unicode_data + b"\nendstream")
    descendant_obj = add_object(("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /BurtgelFont /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> " f"/FontDescriptor {descriptor_obj} 0 R /DW 600 /W [{' '.join(width_entries)}] /CIDToGIDMap {cid_to_gid_obj} 0 R >>").encode("utf-8"))
    font_obj = add_object(("<< /Type /Font /Subtype /Type0 /BaseFont /BurtgelFont /Encoding /Identity-H " f"/DescendantFonts [{descendant_obj} 0 R] /ToUnicode {to_unicode_obj} 0 R >>").encode("utf-8"))
    page_object_ids = []
    for content in page_contents:
        content_obj = add_object(f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream")
        page_object_ids.append(add_object(f"<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_obj} 0 R >> >> /Contents {content_obj} 0 R >>".encode("utf-8")))
    objects[pages_obj - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{obj} 0 R' for obj in page_object_ids)}] /Count {len(page_object_ids)} >>".encode("utf-8")
    catalog_obj = add_object(f"<< /Type /Catalog /Pages {pages_obj} 0 R >>".encode("utf-8"))
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_start = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_obj} 0 R >>\nstartxref\n{xref_start}\n%%EOF".encode("ascii"))
    return bytes(output)


def custom_register_export_matrix(conn, register):
    columns = list_custom_register_columns(conn, register["id"])
    _, row_entries = get_custom_register_grid(conn, register["id"])
    headers = ["№"] + [column["name"] for column in columns] + ["Сүүлд өөрчилсөн"]
    matrix = [headers]
    export_lines = [register["title"], register["description"], f"Үүсгэсэн огноо: {format_dt(now_utc().isoformat())}", "", " | ".join(headers)]
    for index, entry in enumerate(reversed(row_entries), start=1):
        row = entry["row"]
        values = entry["values"]
        rendered_row = [str(index)] + [values.get(column["slug"], "") for column in columns] + [format_dt(row["updated_at"])]
        matrix.append(rendered_row)
        export_lines.append(" | ".join(rendered_row))
    if len(matrix) == 1:
        matrix.append(["-", "Бүртгэл хоосон байна."] + [""] * max(len(columns) - 1, 0) + [""])
        export_lines.append("Бүртгэл хоосон байна.")
    return matrix, export_lines


def send_bytes(start_response, payload, content_type, filename=None, disposition="attachment"):
    headers = [("Content-Type", content_type), ("Content-Length", str(len(payload)))]
    if filename:
        headers.append(("Content-Disposition", f"{disposition}; filename*=UTF-8''{quote(filename)}"))
    start_response("200 OK", headers)
    return [payload]
def nav_links(user):
    if not user:
        return ""
    if user["is_admin"]:
        links = ['<a href="/dashboard">Хяналтын самбар</a>', '<a href="/departments">Хэлтсүүдийн хөрөнгө</a>']
        links.append('<a href="/users">Хэрэглэгчид</a>')
        links.append('<a href="/kpi">Хяналтын KPI</a>')
        links.append('<a href="/permissions">Баганын эрх</a>')
        links.append('<a href="/audit">Аудит лог</a>')
    else:
        links = ['<a href="/departments">Мэдээллийн хөрөнгийн нэгдсэн бүртгэл</a>']
    links.append('<a href="/account/password">Нууц үг солих</a>')
    links.append('<form method="post" action="/logout" class="inline-form"><button type="submit">Гарах</button></form>')
    return "".join(f"<li>{item}</li>" for item in links)


def render_page(title, user, content, notice=""):
    auth_summary = ""
    topbar_controls = ""
    brand_text_raw = "МАБ-ын Хяналтын Платформ" if user and user["is_admin"] else "Хэлтсийн Мэдээллийн Хөрөнгийн Бүртгэлийн Платформ"
    brand_text = brand_text_raw
    subtitle = ""
    shell_class = "shell auth-shell" if not user else "shell"
    topbar_class = "topbar auth-topbar" if not user else "topbar"
    brand_lockup_class = "brand-lockup auth-brand-lockup" if not user else "brand-lockup"
    layout = (
        f'<div class="content-grid"><aside class="sidebar"><ul class="nav">{nav_links(user)}</ul></aside><main class="main">{fmt_notice(notice)}{content}</main></div>'
        if user
        else f'<main class="main auth-main">{fmt_notice(notice)}{content}</main>'
    )
    if user:
        dept_label = "Бүх хэлтэс" if user["is_admin"] else html.escape(user["department_name"] or "-")
        auth_summary = (
            f'<div class="user-chip"><strong>{html.escape(user["username"])}</strong>'
            f'<span>{dept_label}</span></div>'
        )
        topbar_controls = (
            '<div class="topbar-actions">'
            '<button type="button" class="button-link ghost theme-toggle" id="theme-toggle" onclick="toggleTheme()">LIGHT MODE</button>'
            f'{auth_summary}'
            '</div>'
        )
    return f"""<!doctype html>
<html lang="mn">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} | {html.escape(brand_text)}</title>
  <script>
    (function() {{
      try {{
        var theme = localStorage.getItem('burtgel-theme') || 'dark';
        document.documentElement.dataset.theme = theme;
      }} catch (error) {{
        document.documentElement.dataset.theme = 'dark';
      }}
    }})();
  </script>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
<script>
function applyTheme(theme) {{
  document.documentElement.dataset.theme = theme;
  try {{
    localStorage.setItem('burtgel-theme', theme);
  }} catch (error) {{}}
  var button = document.getElementById('theme-toggle');
  if (button) {{
    button.textContent = theme === 'light' ? 'DARK MODE' : 'LIGHT MODE';
  }}
}}
function toggleTheme() {{
  var nextTheme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  applyTheme(nextTheme);
}}
function toggleVisibility(elementId, button) {{
  var element = document.getElementById(elementId);
  if (!element) return;
  var isHidden = element.hasAttribute('hidden');
  if (isHidden) {{
    element.removeAttribute('hidden');
  }} else {{
    element.setAttribute('hidden', 'hidden');
  }}
  if (button) {{
    var openLabel = button.getAttribute('data-open-label');
    var closeLabel = button.getAttribute('data-close-label');
    if (openLabel || closeLabel) {{
      button.textContent = isHidden ? (closeLabel || openLabel || button.textContent) : (openLabel || closeLabel || button.textContent);
    }} else {{
      button.textContent = isHidden ? '−' : '+';
    }}
    button.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
  }}
}}
function copyTextFromElement(elementId, button) {{
  const element = document.getElementById(elementId);
  if (!element) return;
  const text = (element.textContent || element.innerText || '').trim();
  const setCopied = () => {{
    if (!button) return;
    const original = button.dataset.originalLabel || button.textContent;
    button.dataset.originalLabel = original;
    button.textContent = 'Хуулагдлаа';
    window.setTimeout(() => {{
      button.textContent = button.dataset.originalLabel;
    }}, 1600);
  }};
  const fallbackCopy = () => {{
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'readonly');
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    try {{
      document.execCommand('copy');
      setCopied();
    }} finally {{
      document.body.removeChild(textarea);
    }}
  }};
  if (navigator.clipboard && window.isSecureContext) {{
    navigator.clipboard.writeText(text).then(setCopied).catch(fallbackCopy);
  }} else {{
    fallbackCopy();
  }}
}}
document.addEventListener('DOMContentLoaded', function() {{
  applyTheme(document.documentElement.dataset.theme || 'dark');
}});
</script>
  <div class="{shell_class}">
    <header class="{topbar_class}">
      <div class="{brand_lockup_class}">
        <img src="{LOGO_ASSET_URL}" alt="Digital Concept logo" class="brand-logo">
        <div class="brand-copy">
          <a href="/dashboard" class="brand">{'<span class="brand-acronym">МАБ</span>' + html.escape(brand_text_raw[3:]) if brand_text_raw.startswith('МАБ') else html.escape(brand_text_raw)}</a>
          {subtitle}
        </div>
      </div>
      {topbar_controls}
    </header>
    {layout}
  </div>
</body>
</html>"""
def not_found(start_response):
    return response(start_response, "404 Not Found", render_page("Олдсонгүй", None, "<h1>Хуудас олдсонгүй</h1>"))


def forbidden(start_response):
    return response(start_response, "403 Forbidden", render_page("Хандах эрхгүй", None, "<h1>Хандах эрхгүй</h1>"))


def login_form(error="", notice="", username=""):
    body = f"""
    <section class="panel panel-narrow auth-panel login-panel">
      <h1>Нэвтрэх</h1>
      <p class="muted">Хэрэглэгчийн нэр болон нууц үгээ оруулж системд нэвтэрнэ үү.</p>
      {fmt_error(error)}
      {fmt_notice(notice)}
      <form method="post" action="/login" class="stack-form">
        <label>Хэрэглэгчийн нэр<input type="text" name="username" value="{html.escape(username)}" required autofocus></label>
        <label>Нууц үг<input type="password" name="password" required></label>
        <button type="submit">Нэвтрэх</button>
      </form>
    </section>
    """
    return render_page("Нэвтрэх", None, body)


def first_access_page(error="", notice="", username=""):
    body = f"""
    <section class="panel panel-narrow auth-panel">
      <h1>Анхны тохиргоо</h1>
      <p class="muted">Админаас бусад хэрэглэгч анхны нэвтрэхдээ өөрийн нууц үгийг өөрөө үүсгэнэ.</p>
      {fmt_error(error)}
      {fmt_notice(notice)}
      <form method="post" action="/first-access" class="stack-form">
        <label>Хэрэглэгчийн нэр<input type="text" name="username" value="{html.escape(username)}" required autofocus></label>
        <label>Шинэ нууц үг<input type="password" name="new_password" required></label>
        <label>Шинэ нууц үг давтах<input type="password" name="confirm_password" required></label>
        <button type="submit">Нууц үг үүсгээд нэвтрэх</button>
      </form>
      <p class="helper">{html.escape(PASSWORD_POLICY_TEXT)}</p>
      <a class="button-link ghost" href="/login">Нэвтрэх хуудас руу буцах</a>
    </section>
    """
    return render_page("Анхны тохиргоо", None, body)


def list_reference_documents():
    return sorted((item for item in STATIC_DIR.glob("*.pdf") if item.is_file()), key=lambda p: p.name.lower())


def resolve_reference_document(raw_name):
    decoded_name = unquote(raw_name)
    candidate_names = {raw_name, decoded_name}
    for value in (raw_name, decoded_name):
        try:
            candidate_names.add(value.encode("latin-1").decode("utf-8"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    for doc in list_reference_documents():
        if doc.name in candidate_names or quote(doc.name) in candidate_names:
            return doc.resolve()
    return None


def render_reference_documents_section(user):
    items = []
    for doc in list_reference_documents():
        view_href = f"/reference-docs/{quote(doc.name)}"
        download_href = f"/reference-docs/{quote(doc.name)}/download"
        admin_update = ""
        if user["is_admin"]:
            admin_update = f"""
            <form method="post" action="/reference-docs/{quote(doc.name)}/replace" enctype="multipart/form-data" class="stack-form upload-form">
              <label>PDF солих<input type="file" name="document" accept="application/pdf" required></label>
              <button type="submit">PDF шинэчлэх</button>
            </form>
            <form method="post" action="/reference-docs/{quote(doc.name)}/delete" class="inline-form" onsubmit="return confirm('Энэ PDF файлыг устгах уу?');">
              <button type="submit" class="button-link ghost">PDF устгах</button>
            </form>
            """
        items.append(
            f"""
            <article class="card">
              <h2>{html.escape(doc.name)}</h2>
              <p class="muted">Төрөл: PDF</p>
              <div class="action-strip">
                <a class="button-link" href="{view_href}">PDF үзэх</a>
                <a class="button-link ghost" href="{download_href}">Татах</a>
              </div>
              {admin_update}
            </article>
            """
        )
    title = "Бодлого, журам" if not user["is_admin"] else "Хэрэглэгчдэд харагдах PDF баримтууд"
    description = "Эдгээр PDF баримтуудыг систем дээрээс шууд үзэж болно." if not user["is_admin"] else "Админ эдгээр PDF баримтыг нэмж, шинэчилж, устгаж болно."
    create_form = ""
    if user["is_admin"]:
        create_form = """
        <form method="post" action="/reference-docs/create" enctype="multipart/form-data" class="stack-form upload-form upload-form-panel">
          <label>Шинэ PDF нэр<input type="text" name="filename" placeholder="example.pdf" required></label>
          <label>PDF файл<input type="file" name="document" accept="application/pdf" required></label>
          <button type="submit">PDF нэмэх</button>
        </form>
        """
    return f"""
    <section class="panel">
      <h2>{html.escape(title)}</h2>
      <p class="muted">{html.escape(description)}</p>
      {create_form}
      <div class="card-grid">{''.join(items) if items else '<p>PDF баримт алга.</p>'}</div>
    </section>
    """


def reference_document_view_page(user, file_path, notice=""):
    raw_href = f"/reference-docs/{quote(file_path.name)}/raw"
    download_href = f"/reference-docs/{quote(file_path.name)}/download"
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(file_path.name)}</h1>
          <p class="muted">PDF баримтын веб харагдац.</p>
        </div>
        <div class="action-strip">
          <a class="button-link ghost" href="/departments">Буцах</a>
          <a class="button-link ghost" href="{download_href}">Татах</a>
        </div>
      </div>
      <iframe src="{raw_href}" class="pdf-frame" title="{html.escape(file_path.name)}"></iframe>
    </section>
    """
    return render_page(file_path.name, user, body, notice)


def departments_page(conn, user, notice=""):
    cards = []
    for department in departments_for_user(conn, user):
        count = conn.execute("SELECT COUNT(*) FROM assets WHERE department_id = ?", (department["id"],)).fetchone()[0]
        cards.append(
            f"""
            <article class="card">
              <h2>{html.escape(department['name'])}</h2>
              <p>{count} хөрөнгө</p>
              <a class="button-link" href="/departments/{html.escape(department['slug'])}/assets">Бүртгэл нээх</a>
            </article>
            """
        )
    page_title = "Хэлтсүүдийн хөрөнгө" if user["is_admin"] else "Мэдээллийн хөрөнгийн нэгдсэн бүртгэл"
    page_description = "Хэрэглэгч өөрийн харьяалах хэлтсийн хөрөнгийг, админ бүх хэлтсийн хөрөнгийг энэ хэсгээс нээнэ." if user["is_admin"] else "Өөрийн харьяалах хэлтсийн мэдээллийн хөрөнгийн бүртгэлийг энэ хэсгээс нээнэ."
    body = f"""
    <section class="panel">
      <h1>{html.escape(page_title)}</h1>
      <p class="muted">{html.escape(page_description)}</p>
      <div class="card-grid">{''.join(cards) if cards else '<p>Энэ хэрэглэгчид хэлтэс оноогоогүй байна.</p>'}</div>
    </section>
    {render_reference_documents_section(user)}
    """
    return render_page(page_title, user, body, notice)


def _audit_sidebar(conn):
    rows = conn.execute(
        """
        SELECT audit_logs.created_at, actor.username AS actor_username,
               audit_logs.action, audit_logs.details
        FROM audit_logs
        LEFT JOIN users AS actor ON actor.id = audit_logs.actor_user_id
        ORDER BY audit_logs.created_at DESC, audit_logs.id DESC
        LIMIT 20
        """
    ).fetchall()
    action_label_map = {
        "login": "Нэвтэрсэн", "logout": "Гарсан", "login_failed": "Нэвтрэх амжилтгүй",
        "first_access": "Анхны нэвтрэлт", "change_password": "Нууц үг солилт",
        "reset_password": "Нууц үг reset", "create": "Үүсгэсэн", "update": "Засварласан",
        "delete": "Устгасан", "update_permissions": "Эрх өөрчлөлт",
    }
    items = []
    for row in rows:
        label = action_label_map.get(row["action"], row["action"])
        items.append(
            f'<div class="audit-feed-item">'
            f'<div class="audit-feed-meta"><span class="audit-feed-actor">{html.escape(row["actor_username"] or "Систем")}</span>'
            f'<span class="audit-feed-time">{format_dt(row["created_at"])}</span></div>'
            f'<div class="audit-feed-action">{html.escape(label)}</div>'
            f'<div class="audit-feed-detail">{html.escape((row["details"] or "")[:80])}</div>'
            f'</div>'
        )
    return (
        '<div class="audit-feed-panel">'
        '<div class="audit-feed-header"><strong>Аудит лог</strong>'
        '<a class="audit-feed-more" href="/audit">Бүгдийг харах →</a></div>'
        + ("".join(items) if items else '<p class="muted">Одоогоор бичлэг алга.</p>')
        + "</div>"
    )


def dashboard_page(conn, user, notice=""):
    if user["is_admin"]:
        total_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        kpi_dirs = conn.execute("SELECT id, name, slug FROM kpi_directories ORDER BY name").fetchall()
        kpi_btns = "".join(
            f'<a class="kpi-dir-btn" href="/kpi/{html.escape(d["slug"])}">{html.escape(d["name"])}</a>'
            for d in kpi_dirs
        )
        kpi_section = f"""
        <section class="panel">
          <div class="heading-row compact-heading-row">
            <div>
              <h2>Хяналтын KPI</h2>
              <p class="muted">KPI лавлах сонгох эсвэл шинэ үүсгэх.</p>
            </div>
            <a class="button-link" href="/kpi">Бүх KPI харах / Нэмэх</a>
          </div>
          <div class="kpi-dir-list">{kpi_btns if kpi_btns else '<p class="muted">Одоогоор KPI лавлах үүсгэгдээгүй байна. Дээрх товчоор нэмнэ үү.</p>'}</div>
        </section>
        """
        main_html = f"""
        <div class="dashboard-page-header">
          <span class="dashboard-title-sm">Хяналтын самбар</span>
          <span class="muted" style="font-size:0.82rem">Нийт хөрөнгө: {total_assets}</span>
        </div>
        {kpi_section}
        {render_custom_registers_overview(conn)}
        {render_admin_documents_overview(conn)}
        """
        body = f"""
        <div class="dashboard-admin-grid">
          <div class="dashboard-main">{main_html}</div>
          {_audit_sidebar(conn)}
        </div>
        """
        return render_page("Хяналтын самбар", user, body, notice)
    body = """
    <section class="panel">
      <h1>Хяналтын самбар</h1>
      <p class="muted">Системийн үндсэн мэдээлэл энд харагдана. Хэлтсийн хөрөнгийн жагсаалтыг зүүн цэсний `Хэлтсүүдийн хөрөнгө` хэсгээс нээнэ үү.</p>
    </section>
    """
    return render_page("Хяналтын самбар", user, body, notice)
def _render_review_frequency_field(user, source):
    current = html.escape(source.get("review_frequency", "") or "")
    if user["is_admin"]:
        options = '<option value="">— Сонгоно уу —</option>'
        for opt in FREQUENCY_OPTIONS:
            sel = "selected" if source.get("review_frequency") == opt else ""
            options += f'<option value="{html.escape(opt)}" {sel}>{html.escape(opt)}</option>'
        return f'<label>Хянах давтамж<select name="review_frequency">{options}</select></label>'
    val = source.get("review_frequency") or "—"
    return f'<label>Хянах давтамж<input type="text" value="{html.escape(val)}" readonly><span class="helper">Энэ талбарыг зөвхөн админ өөрчилнө.</span></label>'


def render_asset_form(action, user, department, values, permissions, error="", submit_label="Хадгалах"):
    source = dict(values) if values else {}
    inputs = []
    for name, label, required in ASSET_FIELDS:
        value = html.escape(source.get(name, ""))
        editable = can_edit_field(user, permissions, name)
        required_attr = " required" if required and editable else ""
        readonly_attr = " readonly" if not editable else ""
        helper = '<span class="helper">Энэ талбарыг зөвхөн админ өөрчилнө.</span>' if not editable else ''
        if name in {"description", "location", "access_right"}:
            field = f'<textarea name="{name}"{required_attr}{readonly_attr}>{value}</textarea>'
        else:
            field = f'<input type="text" name="{name}" value="{value}"{required_attr}{readonly_attr}>'
        inputs.append(f"<label>{html.escape(label)}{field}{helper}</label>")
    body = f"""
    <section class=\"panel\">
      <div class=\"heading-row\">
        <div>
          <h1>{html.escape(department['name'])}</h1>
          <p class=\"muted\">Энэ хэлтсийн хөрөнгийн бүртгэлийг удирдана.</p>
        </div>
        <a class=\"button-link ghost\" href=\"/departments/{html.escape(department['slug'])}/assets\">Жагсаалт руу буцах</a>
      </div>
      {fmt_error(error)}
      <form method=\"post\" action=\"{action}\" class=\"asset-form\">
        {''.join(inputs)}
        <div class=\"review-section\">
          <h3 class=\"review-section-title\">Хяналтын тохиргоо</h3>
          {_render_review_frequency_field(user, source)}
        </div>
        <div class=\"actions\"><button type=\"submit\">{submit_label}</button></div>
      </form>
    </section>
    """
    return body


def asset_list_page(conn, user, department, notice=""):
    rows = conn.execute(
        """
        SELECT id, asset_name, asset_type, asset_group_code, owner, asset_category, updated_at, review_frequency
        FROM assets
        WHERE department_id = ?
        ORDER BY asset_name COLLATE NOCASE
        """,
        (department["id"],),
    ).fetchall()
    body_rows = []
    for row in rows:
        body_rows.append(
            f"""
            <tr>
              <td>{html.escape(row['asset_name'])}</td>
              <td>{html.escape(row['asset_type'])}</td>
              <td>{html.escape(row['asset_group_code'])}</td>
              <td>{html.escape(row['owner'])}</td>
              <td>{html.escape(row['asset_category'])}</td>
              <td>{format_dt(row['updated_at'])}</td>
              <td>{format_time_left(row['review_frequency'], row['updated_at'])}</td>
              <td class=\"table-actions\">
                <div class=\"action-strip\">
                  <a class=\"button-link ghost small\" href=\"/departments/{html.escape(department['slug'])}/assets/{row['id']}/edit\">Засах</a>
                  <a class=\"button-link ghost small\" href=\"/departments/{html.escape(department['slug'])}/assets/{row['id']}\">Дэлгэрэнгүй</a>
                  <form method=\"post\" action=\"/departments/{html.escape(department['slug'])}/assets/{row['id']}/delete\" class=\"inline-form\" onsubmit="return confirm(\'Устгахдаа итгэлтэй байна уу?\')">
                    <button type=\"submit\" class=\"link-button danger\">Устгах</button>
                  </form>
                </div>
              </td>
            </tr>
            """
        )
    body = f"""
    <section class=\"panel\">
      <div class=\"heading-row\">
        <div>
          <h1>{html.escape(department['name'])}</h1>
          <p class=\"muted\">Хэрэглэгч зөвхөн өөрийн хэлтсийн бүртгэлийг харж, удирдана.</p>
        </div>
        <a class=\"button-link\" href=\"/departments/{html.escape(department['slug'])}/assets/new\">Хөрөнгө нэмэх</a>
      </div>
      <div class=\"table-wrap\">
        <table>
          <thead>
            <tr>{''.join(f'<th>{label}</th>' for _, label in LIST_FIELDS)}<th>Үлдсэн хугацаа</th><th></th></tr>
          </thead>
          <tbody>
            {''.join(body_rows) if body_rows else '<tr><td colspan="8">Энэ хэлтэст одоогоор хөрөнгө бүртгэгдээгүй байна.</td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
    """
    return render_page(f"{department['name']} хөрөнгө", user, body, notice)

def asset_detail_page(user, department, asset, notice=""):
    items = []
    for field_name, label, _ in ASSET_FIELDS:
        items.append(
            f"""
            <article class="detail-item">
              <div class="detail-label">{html.escape(label)}</div>
              <div class="detail-value">{format_multiline(asset[field_name])}</div>
            </article>
            """
        )
    items.append(
        f"""
        <article class="detail-item">
          <div class="detail-label">Сүүлд өөрчилсөн</div>
          <div class="detail-value">{format_dt(asset['updated_at'])}</div>
        </article>
        """
    )
    if asset["review_frequency"]:
        items.append(
            f"""
            <article class="detail-item">
              <div class="detail-label">Хянах давтамж</div>
              <div class="detail-value">{html.escape(asset['review_frequency'])}</div>
            </article>
            <article class="detail-item">
              <div class="detail-label">Үлдсэн хугацаа</div>
              <div class="detail-value">{format_time_left(asset['review_frequency'], asset['updated_at'])}</div>
            </article>
            """
        )
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(asset['asset_name'])}</h1>
          <p class="muted">Excel файлаас орж ирсэн бүх талбар энд харагдана.</p>
        </div>
        <div class="action-strip">
          <a class="button-link ghost" href="/departments/{html.escape(department['slug'])}/assets">Буцах</a>
          <a class="button-link ghost" href="/departments/{html.escape(department['slug'])}/assets/{asset['id']}/edit">Засах</a>
        </div>
      </div>
      <div class="detail-grid">{''.join(items)}</div>
    </section>
    """
    return render_page(asset['asset_name'], user, body, notice)


def password_change_page(user, error="", notice=""):
    is_otp_flow = password_setup_required(user)
    title = "Нэг удаагийн нууц үг баталгаажуулах" if is_otp_flow else "Нууц үг солих"
    intro = (
        "Админаас авсан нэг удаагийн нууц үгээ оруулаад доорх шаардлагыг хангасан шинэ нууц үг үүсгэнэ үү. Энэ алхмыг дуусгахаас өмнө системийн бусад хэсэгт хандах боломжгүй."
        if is_otp_flow
        else "Одоогийн нууц үгээ баталгаажуулаад шинэ нууц үгээ оруулна уу."
    )
    current_label = "Нэг удаагийн нууц үг (OTP)" if is_otp_flow else "Одоогийн нууц үг"
    submit_label = "OTP баталгаажуулаад нууц үг шинэчлэх" if is_otp_flow else "Шинэчлэх"
    body = f"""
    <section class="panel panel-narrow auth-panel">
      <h1>{html.escape(title)}</h1>
      <p class="muted">{html.escape(intro)}</p>
      {fmt_error(error)}
      {fmt_notice(notice)}
      <form method="post" action="/account/password" class="stack-form">
        <label>{html.escape(current_label)}<input type="password" name="current_password" required autofocus></label>
        <label>Шинэ нууц үг<input type="password" name="new_password" required></label>
        <label>Шинэ нууц үг давтах<input type="password" name="confirm_password" required></label>
        <button type="submit">{html.escape(submit_label)}</button>
      </form>
      <div class="policy-box">
        <strong>Нууц үгийн шаардлага</strong>
        <ul class="policy-list">
          <li>Хамгийн багадаа 12 тэмдэгт байна.</li>
          <li>Дор хаяж 1 том үсэг байна.</li>
          <li>Дор хаяж 1 жижиг үсэг байна.</li>
          <li>Дор хаяж 1 тоо байна.</li>
          <li>Дор хаяж 1 тусгай тэмдэгт байна.</li>
          <li>Зай агуулахгүй байна.</li>
        </ul>
      </div>
    </section>
    """
    return render_page(title, user, body, notice)


def reset_password_page(user, target_user, error="", notice="", temp_password=""):
    dept_label = target_user["department_name"] or "Бүх хэлтэс"
    temp_markup = ""
    if temp_password:
        temp_markup = (
            '<div class="secret-box">'
            '<div class="secret-label">Нэг удаагийн нууц үг (OTP)</div>'
            f'<code id="otp-secret">{html.escape(temp_password)}</code>'
            '<div class="secret-actions">'
            "<button type=\"button\" class=\"button-link\" onclick=\"navigator.clipboard.writeText(document.getElementById('otp-secret').innerText)\">Хуулах</button>"
            '</div>'
            '<p class="helper">Энэ OTP-г яг одоо хуулж хэрэглэгчид өгнө үү. Дараагийн нэвтрэх үед хэрэглэгч энэ OTP-г оруулаад өөрийн шинэ нууц үгийг заавал үүсгэнэ.</p>'
            '</div>'
        )
    body = f"""
    <section class="panel panel-narrow auth-panel">
      <h1>Нэг удаагийн нууц үг үүсгэх</h1>
      <p class="muted"><strong>{html.escape(target_user['username'])}</strong> хэрэглэгчид зориулж систем автоматаар нэг удаагийн нууц үг үүсгэнэ. Админ шинэ нууц үг гараар оруулахгүй. Хэлтэс: {html.escape(dept_label)}</p>
      {fmt_error(error)}
      {fmt_notice(notice)}
      {temp_markup}
      <form method="post" action="/users/{target_user['id']}/reset-password" class="stack-form">
        <button type="submit">OTP үүсгээд харуулах</button>
      </form>
      <a class="button-link ghost" href="/users">Хэрэглэгчид рүү буцах</a>
    </section>
    """
    return render_page("Нэг удаагийн нууц үг үүсгэх", user, body, notice)


def users_page(conn, user, notice="", error=""):
    user_rows = conn.execute(
        """
        SELECT users.id, users.username, users.is_admin, users.is_active, users.last_login_at,
               users.must_change_password, users.password_hash, users.password_changed_at,
               departments.name AS department_name
        FROM users
        LEFT JOIN departments ON departments.id = users.department_id
        ORDER BY users.is_admin DESC, users.username
        """
    ).fetchall()
    rows = []
    for row in user_rows:
        dept = row["department_name"] or "Бүх хэлтэс"
        role = "Админ" if row["is_admin"] else "Хэлтэс"
        active_label = "Идэвхтэй" if row["is_active"] else '<span style="color:var(--danger)">Идэвхгүй</span>'
        if not row["password_hash"]:
            password_state = "Анхны тохиргоо хүлээгдэж байна"
        elif row["must_change_password"]:
            password_state = "OTP идэвхтэй, нууц үг шинэчлэх хүлээгдэж байна"
        else:
            password_state = "Идэвхтэй"
        is_self = row["id"] == user["id"]
        delete_btn = (
            f'<form method="post" action="/users/{row["id"]}/delete" style="display:inline" onsubmit="return confirm(\'{html.escape(row["username"])} хэрэглэгчийг устгах уу?\')"><button class="button-link ghost small danger" type="submit">Устгах</button></form>'
            if not is_self else ""
        )
        rows.append(
            f"""
            <tr>
              <td>{html.escape(row['username'])}</td>
              <td>{html.escape(dept)}</td>
              <td>{role}</td>
              <td>{active_label}</td>
              <td>{format_dt(row['last_login_at'])}</td>
              <td>{password_state}</td>
              <td class="table-actions">
                <div class="action-strip">
                  <a class="button-link ghost small" href="/users/{row['id']}/edit">Засах</a>
                  <a class="button-link ghost small" href="/users/{row['id']}/reset-password">OTP үүсгэх</a>
                  {delete_btn}
                </div>
              </td>
            </tr>
            """
        )
    body = f"""
    <section class="panel">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem">
        <h1>Хэрэглэгчид</h1>
        <a class="button-link" href="/users/create">+ Хэрэглэгч нэмэх</a>
      </div>
      {fmt_error(error)}
    </section>
    <section class="panel">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Хэрэглэгчийн нэр</th>
              <th>Хэлтэс</th>
              <th>Эрх</th>
              <th>Төлөв</th>
              <th>Сүүлд нэвтэрсэн</th>
              <th>Нууц үгийн төлөв</th>
              <th></th>
            </tr>
          </thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """
    return render_page("Хэрэглэгчид", user, body, notice)


def user_create_page(departments, error="", values=None):
    values = values or {}
    dept_options = '<option value="">— Хэлтэс сонгоно уу —</option>'
    for d in departments:
        sel = 'selected' if str(values.get("department_id", "")) == str(d["id"]) else ""
        dept_options += f'<option value="{d["id"]}" {sel}>{html.escape(d["name"])}</option>'
    is_admin_checked = 'checked' if values.get("is_admin") == "1" else ""
    body = f"""
    <section class="panel panel-narrow">
      <h1>Шинэ хэрэглэгч нэмэх</h1>
      {fmt_error(error)}
      <form method="post" action="/users/create" class="stack-form">
        <label>Хэрэглэгчийн нэр<input type="text" name="username" value="{html.escape(values.get('username', ''))}" required autofocus></label>
        <label>Хэлтэс
          <select name="department_id">{dept_options}</select>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" name="is_admin" value="1" {is_admin_checked}> Админ эрх
        </label>
        <p class="muted" style="margin:0">Хэрэглэгч нэвтэрч орохдоо нэг удаагийн нууц үгийг ашиглана. OTP-г хэрэглэгч үүссэний дараа үүсгэнэ үү.</p>
        <div style="display:flex;gap:0.5rem">
          <button type="submit">Үүсгэх</button>
          <a class="button-link ghost" href="/users">Буцах</a>
        </div>
      </form>
    </section>
    """
    return body


def user_edit_page(conn, target_user, departments, dept_perms, error="", values=None):
    values = values or target_user
    dept_options = '<option value="">— Хэлтэс сонгоогүй (Бүх хэлтэс) —</option>'
    selected_dept = str(values.get("department_id") or target_user["department_id"] or "")
    for d in departments:
        sel = 'selected' if str(d["id"]) == selected_dept else ""
        dept_options += f'<option value="{d["id"]}" {sel}>{html.escape(d["name"])}</option>'
    is_admin_checked = 'checked' if (values.get("is_admin") if values is not target_user else target_user["is_admin"]) else ""
    is_active_checked = 'checked' if (values.get("is_active", "1") != "0" if values is not target_user else target_user["is_active"]) else ""

    perm_rows = ""
    for d in departments:
        p = dept_perms.get(d["id"], {})
        r_checked = 'checked' if p.get("can_read") else ""
        u_checked = 'checked' if p.get("can_update") else ""
        perm_rows += f"""
        <tr>
          <td>{html.escape(d['name'])}</td>
          <td style="text-align:center"><input type="checkbox" name="read_{d['id']}" value="1" {r_checked}></td>
          <td style="text-align:center"><input type="checkbox" name="update_{d['id']}" value="1" {u_checked}></td>
        </tr>"""

    body = f"""
    <section class="panel panel-narrow">
      <h1>{html.escape(target_user['username'])} — Засах</h1>
      {fmt_error(error)}
      <form method="post" action="/users/{target_user['id']}/edit" class="stack-form">
        <label>Хэрэглэгчийн нэр<input type="text" name="username" value="{html.escape(target_user['username'])}" required></label>
        <label>Хэлтэс (үндсэн)
          <select name="department_id">{dept_options}</select>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" name="is_admin" value="1" {is_admin_checked}> Админ эрх
        </label>
        <label class="checkbox-label">
          <input type="checkbox" name="is_active" value="1" {is_active_checked}> Идэвхтэй
        </label>
        <h2 style="margin-top:1.5rem">Хэлтсийн хандах эрх</h2>
        <p class="muted" style="margin:0">Админ эрхтэй хэрэглэгчид бүх хэлтэст автоматаар хандана.</p>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Хэлтэс</th><th style="text-align:center">Унших</th><th style="text-align:center">Засах / Нэмэх / Устгах</th></tr>
            </thead>
            <tbody>{perm_rows}</tbody>
          </table>
        </div>
        <div style="display:flex;gap:0.5rem;margin-top:1rem">
          <button type="submit">Хадгалах</button>
          <a class="button-link ghost" href="/users">Буцах</a>
        </div>
      </form>
    </section>
    """
    return body




def kpi_list_page(conn, user, notice="", error=""):
    dirs = conn.execute("SELECT * FROM kpi_directories ORDER BY name").fetchall()
    rows = "".join(
        f"""<tr>
          <td><a class="table-link" href="/kpi/{html.escape(d['slug'])}">{html.escape(d['name'])}</a></td>
          <td class="muted">{html.escape(d['description'])}</td>
          <td>{format_dt(d['created_at'])}</td>
          <td class="table-actions"><div class="action-strip">
            <a class="button-link ghost small" href="/kpi/{html.escape(d['slug'])}">Нээх</a>
            <form method="post" action="/kpi/{html.escape(d['slug'])}/delete" class="inline-form"
                  onsubmit="return confirm('{html.escape(d['name'])} устгах уу?')">
              <button class="link-button danger" type="submit">Устгах</button>
            </form>
          </div></td>
        </tr>"""
        for d in dirs
    )
    body = f"""
    <section class="panel">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap">
        <div><h1>Хяналтын KPI</h1><p class="muted">KPI лавлахуудыг энд удирдана.</p></div>
      </div>
      {fmt_error(error)}
      <form method="post" action="/kpi/create" class="stack-form" style="margin-top:1rem;max-width:480px">
        <label>Лавлахын нэр<input type="text" name="name" required placeholder="Жишээ: Борлуулалтын KPI"></label>
        <label>Тайлбар (заавал биш)<input type="text" name="description" placeholder="Энэ лавлахын зорилго..."></label>
        <button type="submit">+ Шинэ лавлах үүсгэх</button>
      </form>
    </section>
    <section class="panel">
      <div class="table-wrap">
        <table>
          <thead><tr><th>Нэр</th><th>Тайлбар</th><th>Үүсгэсэн</th><th></th></tr></thead>
          <tbody>{rows if rows else '<tr><td colspan="4" class="muted">Одоогоор лавлах алга.</td></tr>'}</tbody>
        </table>
      </div>
    </section>
    """
    return render_page("Хяналтын KPI", user, body, notice)


def kpi_directory_page(conn, user, directory, notice="", error=""):
    freq_options = "".join(f'<option value="{o}">{html.escape(o)}</option>' for o in FREQUENCY_OPTIONS)
    items = conn.execute(
        "SELECT * FROM kpi_items WHERE directory_id = ? ORDER BY order_num, id",
        (directory["id"],),
    ).fetchall()
    body_rows = []
    for i, item in enumerate(items, 1):
        timeleft = format_days_until(item["due_date"])
        freq_sel = "".join(
            f'<option value="{o}" {"selected" if o == item["frequency"] else ""}>{html.escape(o)}</option>'
            for o in FREQUENCY_OPTIONS
        )
        due_val = html.escape(item["due_date"] if item["due_date"] else "")
        body_rows.append(f"""
        <tr>
          <td>{i}</td>
          <td><form method="post" action="/kpi/{html.escape(directory['slug'])}/rows/{item['id']}/edit" class="kpi-inline-form">
            <input type="text" name="indicator" value="{html.escape(item['indicator'])}" class="kpi-cell-input">
          </td>
          <td><input type="text" name="description" value="{html.escape(item['description'])}" class="kpi-cell-input"></td>
          <td><input type="text" name="formula" value="{html.escape(item['formula'])}" class="kpi-cell-input"></td>
          <td><input type="text" name="target_level" value="{html.escape(item['target_level'])}" class="kpi-cell-input" style="width:60px"></td>
          <td><select name="frequency" class="kpi-cell-select">{freq_sel}</select></td>
          <td><input type="date" name="due_date" value="{due_val}" class="kpi-cell-input"></td>
          <td>{timeleft}</td>
          <td class="table-actions"><button class="button-link ghost small" type="submit">Хадгалах</button></form>
            <form method="post" action="/kpi/{html.escape(directory['slug'])}/rows/{item['id']}/delete"
                  class="inline-form" onsubmit="return confirm('Мөрийг устгах уу?')">
              <button class="link-button danger" type="submit">Устгах</button>
            </form>
          </td>
        </tr>""")
    add_row = f"""
    <tr class="kpi-add-row">
      <form method="post" action="/kpi/{html.escape(directory['slug'])}/rows/new">
      <td class="muted">*</td>
      <td><input type="text" name="indicator" class="kpi-cell-input" placeholder="Шалгуур үзүүлэлт" required></td>
      <td><input type="text" name="description" class="kpi-cell-input" placeholder="Тайлбар"></td>
      <td><input type="text" name="formula" class="kpi-cell-input" placeholder="Хэмжих нэгж / Томьёо"></td>
      <td><input type="text" name="target_level" class="kpi-cell-input" placeholder="Зорилт" style="width:60px"></td>
      <td><select name="frequency" class="kpi-cell-select"><option value="">— сонго —</option>{freq_options}</select></td>
      <td><input type="date" name="due_date" class="kpi-cell-input"></td>
      <td>—</td>
      <td><button class="button-link small" type="submit">+ Нэмэх</button></form></td>
    </tr>"""
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(directory['name'])}</h1>
          <p class="muted">{html.escape(directory['description'])}</p>
        </div>
        <a class="button-link ghost" href="/kpi">← Лавлахын жагсаалт</a>
      </div>
      {fmt_error(error)}
    </section>
    <section class="panel">
      <div class="table-wrap">
        <table class="kpi-table">
          <thead>
            <tr>
              <th style="width:36px">№</th>
              <th>Гүйцэтгэлийн шалгуур үзүүлэлт</th>
              <th>Тайлбар</th>
              <th>Хэмжих нэгж / Томьёо</th>
              <th style="width:80px">Зорилтот түвшин</th>
              <th style="width:140px">Хянах давтамж</th>
              <th style="width:130px">Дуусах өдөр</th>
              <th style="width:130px">Үлдсэн хугацаа</th>
              <th style="width:130px"></th>
            </tr>
          </thead>
          <tbody>
            {''.join(body_rows)}
            {add_row}
          </tbody>
        </table>
      </div>
    </section>
    """
    return render_page(directory["name"], user, body, notice)


def render_custom_registers_overview(conn):
    rows = []
    manage_rows = []
    for register in list_custom_registers(conn):
        slug = html.escape(register["slug"])
        rows.append(
            f"""
            <tr>
              <td><a class="table-link" href="/custom-registers/{slug}">{html.escape(register['title'])}</a></td>
              <td class="table-actions">
                <div class="action-strip">
                  <a class="button-link ghost small" href="/custom-registers/{slug}/export.xlsx">Excel</a>
                  <a class="button-link ghost small" href="/custom-registers/{slug}/export.pdf">PDF</a>
                </div>
              </td>
            </tr>
            """
        )
        manage_rows.append(
            f"""
            <tr>
              <td>{html.escape(register['title'])}</td>
              <td>
                <form method="post" action="/custom-registers/{slug}/rename" class="inline-rename-form split-rename-form">
                  <input type="text" name="title" value="{html.escape(register['title'])}" class="table-inline-input compact-input" required>
                  <button type="submit" class="button-link ghost small">Нэр өөрчлөх</button>
                </form>
              </td>
              <td class="table-actions">
                <form method="post" action="/custom-registers/{slug}/delete" class="inline-form" onsubmit="return confirm('Энэ бүртгэлийг бүх мөр, баганатай нь устгах уу?');">
                  <button type="submit" class="link-button danger">Устгах</button>
                </form>
              </td>
            </tr>
            """
        )
    return f"""
    <section class="panel">
      <div class="heading-row compact-heading-row">
        <div>
          <h2>Бүртгэлүүд</h2>
          <p class="muted">Бүртгэлийн нэр дээр дарж багана болон өгөгдлөө удирдана.</p>
        </div>
        <button type="button" class="button-link ghost manage-columns-button" onclick="toggleVisibility('custom-register-manage-form', this)" data-open-label="Бүртгэл засах" data-close-label="Бүртгэл засах" aria-expanded="false">Бүртгэл засах</button>
      </div>
      <div id="custom-register-manage-form" class="toggle-form manage-columns-panel" hidden>
        <form method="post" action="/custom-registers/create" class="stack-form upload-form upload-form-panel compact-manage-form">
          <label>Бүртгэлийн нэр<input type="text" name="title" placeholder="Жишээ: Гэрээний бүртгэл" required></label>
          <button type="submit">Бүртгэл үүсгэх</button>
        </form>
        <div class="nested-table-wrap table-wrap">
          <table>
            <thead>
              <tr><th>Бүртгэл</th><th>Нэр өөрчлөх</th><th></th></tr>
            </thead>
            <tbody>{''.join(manage_rows) if manage_rows else '<tr><td colspan="3">Одоогоор бүртгэл алга.</td></tr>'}</tbody>
          </table>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Нэр</th><th></th></tr>
          </thead>
          <tbody>{''.join(rows) if rows else '<tr><td colspan="2">Одоогоор бүртгэл алга.</td></tr>'}</tbody>
        </table>
      </div>
    </section>
    """


def custom_register_row_form_page(user, register, columns, values=None, error="", submit_label="Мөр хадгалах", action_path=""):
    source = values or {}
    fields = []
    for column in columns:
        fields.append(
            f'<label>{html.escape(column["name"])}<textarea name="column_{column["id"]}">{html.escape(source.get(column["id"], ""))}</textarea></label>'
        )
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(register['title'])}</h1>
          <p class="muted">Бүртгэлийн мөрийн мэдээллийг бөглөнө.</p>
        </div>
        <a class="button-link ghost" href="/custom-registers/{html.escape(register['slug'])}">Буцах</a>
      </div>
      {fmt_error(error)}
      <form method="post" action="{action_path}" class="asset-form">
        {''.join(fields) if fields else '<p>Эхлээд багана нэмнэ үү.</p>'}
        <div class="actions"><button type="submit"{' disabled' if not fields else ''}>{html.escape(submit_label)}</button></div>
      </form>
    </section>
    """
    return render_page(register["title"], user, body)







def custom_register_detail_page(conn, user, register, notice=""):
    columns, row_entries = get_custom_register_grid(conn, register["id"])
    manage_toggle_id = f"custom-register-column-manage-{register['id']}"
    row_form_id = f"custom-register-row-create-{register['id']}"
    manage_rows = []
    for column in columns:
        manage_rows.append(
            f"""
            <tr>
              <td>{html.escape(column['name'])}</td>
              <td>
                <form method="post" action="/custom-registers/{html.escape(register['slug'])}/columns/{column['id']}/rename" class="inline-form inline-rename-form split-rename-form">
                  <input type="text" name="name" value="{html.escape(column['name'])}" class="table-inline-input compact-input" required>
                  <button type="submit" class="button-link ghost small">Нэр хадгалах</button>
                </form>
              </td>
              <td class="table-actions">
                <form method="post" action="/custom-registers/{html.escape(register['slug'])}/columns/{column['id']}/delete" class="inline-form" onsubmit="return confirm('Энэ баганыг устгах уу? Холбогдох бүх утга бас устна.');">
                  <button type="submit" class="link-button danger">Устгах</button>
                </form>
              </td>
            </tr>
            """
        )
    entry_row = ""
    if columns:
        inputs = ''.join(
            f'<td><input class="table-inline-input" type="text" name="column_{column["id"]}" form="{row_form_id}" placeholder="{html.escape(column["name"])}"></td>'
            for column in columns
        )
        entry_row = f"""
        <tr>
          <td>Шинэ</td>
          {inputs}
          <td>-</td>
          <td class="table-actions"><button type="submit" form="{row_form_id}" class="button-link small table-inline-submit">Хадгалах</button></td>
        </tr>
        """
    body_rows = []
    for index, entry in enumerate(reversed(row_entries), start=1):
        row = entry["row"]
        values = entry["values"]
        cells = [f"<td>{index}</td>"]
        for column in columns:
            cells.append(f"<td>{format_multiline(values.get(column['slug'], ''))}</td>")
        cells.append(f"<td>{format_dt(row['updated_at'])}</td>")
        cells.append(
            f"""
            <td class="table-actions">
              <div class="action-strip">
                <a class="button-link ghost small" href="/custom-registers/{html.escape(register['slug'])}/rows/{row['id']}/edit">Засах</a>
                <form method="post" action="/custom-registers/{html.escape(register['slug'])}/rows/{row['id']}/delete" class="inline-form" onsubmit="return confirm('Энэ мөрийг устгах уу?');">
                  <button type="submit" class="link-button danger">Устгах</button>
                </form>
              </div>
            </td>
            """
        )
        body_rows.append(f"<tr>{''.join(cells)}</tr>")
    manage_panel = f"""
      <div id="{manage_toggle_id}" class="toggle-form" hidden>
        <div class="manage-columns-panel">
          <form method="post" action="/custom-registers/{html.escape(register['slug'])}/columns/create" class="stack-form upload-form upload-form-panel compact-manage-form">
            <label>Баганын нэр<input type="text" name="name" placeholder="Жишээ: Хугацаа" required></label>
            <button type="submit">Багана нэмэх</button>
          </form>
          <div class="table-wrap nested-table-wrap">
            <table>
              <thead>
                <tr><th>Багана</th><th>Нэр өөрчлөх</th><th></th></tr>
              </thead>
              <tbody>{''.join(manage_rows) if manage_rows else '<tr><td colspan="3">Одоогоор багана алга.</td></tr>'}</tbody>
            </table>
          </div>
        </div>
      </div>
    """
    body = f"""
    <section class="panel">
      <h1>{html.escape(register['title'])}</h1>
      <p class="muted">{html.escape(register['description'] or 'Тайлбар оруулаагүй байна.')}</p>
    </section>
    <section class="panel">
      <div class="heading-row compact-heading-row">
        <div>
          <h2>Жагсаалт</h2>
          <p class="muted">Жагсаалтын эхний мөрөнд утга оруулаад шууд хадгална.</p>
        </div>
        <button type="button" class="button-link ghost manage-columns-button" onclick="toggleVisibility('{manage_toggle_id}', this)" data-open-label="Багана удирдах" data-close-label="Багана удирдах" aria-expanded="false">Багана удирдах</button>
      </div>
      {manage_panel}
      <form method="post" action="/custom-registers/{html.escape(register['slug'])}/rows/new" id="{row_form_id}"></form>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>№</th>{''.join(f'<th>{html.escape(column["name"])}</th>' for column in columns)}<th>Сүүлд өөрчилсөн</th><th></th></tr>
          </thead>
          <tbody>{''.join(body_rows) if body_rows else f'<tr><td colspan="{len(columns) + 3}">Одоогоор мөр алга.</td></tr>'}{entry_row if columns else ''}</tbody>
        </table>
      </div>
    </section>
    """
    return render_page(register["title"], user, body, notice)

def permissions_page(conn, user, notice=""):
    departments = list(conn.execute("SELECT * FROM departments ORDER BY name"))
    panels = []
    for department in departments:
        permissions = get_department_permissions(conn, department["id"])
        items = []
        for field_name, label, _ in ASSET_FIELDS:
            checked = " checked" if permissions.get(field_name, True) else ""
            items.append(
                f'<label class="checkbox-card"><input type="checkbox" name="perm__{department["id"]}__{field_name}" value="1"{checked}> {html.escape(label)}</label>'
            )
        panels.append(
            f"""
            <section class="panel">
              <h2>{html.escape(department['name'])}</h2>
              <p class="muted">Энэ хэлтсийн энгийн хэрэглэгч ямар талбарыг засаж болохыг тохируулна.</p>
              <div class="permissions-grid">{''.join(items)}</div>
            </section>
            """
        )
    body = f"""
    <form method="post" action="/permissions" class="stack-form">
      {''.join(panels)}
      <section class="panel"><button type="submit">Эрх шинэчлэх</button></section>
    </form>
    """
    return render_page("Баганын эрх", user, body, notice)
def list_admin_documents():
    allowed_suffixes = {".pdf", ".doc", ".docx", ".xls", ".xlsx"}
    docs = []
    for item in sorted(DOCS_DIR.iterdir(), key=lambda p: p.name.lower()):
        if not item.is_file() or item.name == DB_PATH.name or item.name.startswith("Хавсралт"):
            continue
        if item.name.startswith(".") or item.name.startswith("burtgel.db"):
            continue
        if item.suffix.lower() not in allowed_suffixes:
            continue
        docs.append(item)
    return docs


def allowed_admin_document_suffixes():
    return {".pdf", ".doc", ".docx", ".xls", ".xlsx"}


def seed_admin_document_categories(conn):
    timestamp = now_utc().isoformat()
    for index, name in enumerate(DEFAULT_ADMIN_DOCUMENT_CATEGORIES, start=1):
        slug = slugify(name)
        conn.execute(
            """
            INSERT OR IGNORE INTO admin_document_categories(slug, name, display_order, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (slug, name, index, timestamp, timestamp),
        )
        conn.execute(
            "UPDATE admin_document_categories SET display_order = ?, updated_at = ? WHERE slug = ?",
            (index, timestamp, slug),
        )
    categories = {row["name"]: row["id"] for row in list_admin_document_categories(conn)}
    for doc in list_admin_documents():
        linked = conn.execute("SELECT 1 FROM admin_document_category_links WHERE file_name = ?", (doc.name,)).fetchone()
        if linked:
            continue
        guessed = guess_admin_document_category_name(doc.name)
        if guessed in categories:
            set_admin_document_category(conn, doc.name, categories[guessed])


def list_admin_document_categories(conn):
    return conn.execute(
        "SELECT * FROM admin_document_categories ORDER BY display_order ASC, name COLLATE NOCASE ASC"
    ).fetchall()


def get_admin_document_category(conn, category_id):
    if not category_id:
        return None
    return conn.execute("SELECT * FROM admin_document_categories WHERE id = ?", (category_id,)).fetchone()


def create_admin_document_category(conn, name):
    clean_name = normalize_text(name)
    if not clean_name:
        return None, "Ангиллын нэр оруулна уу."
    existing = conn.execute(
        "SELECT id FROM admin_document_categories WHERE LOWER(name) = LOWER(?)",
        (clean_name,),
    ).fetchone()
    if existing:
        return None, "Ийм нэртэй ангилал аль хэдийн байна."
    timestamp = now_utc().isoformat()
    next_order = conn.execute("SELECT COALESCE(MAX(display_order), 0) + 1 FROM admin_document_categories").fetchone()[0]
    slug = unique_slug(conn, "admin_document_categories", clean_name)
    conn.execute(
        """
        INSERT INTO admin_document_categories(slug, name, display_order, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (slug, clean_name, next_order, timestamp, timestamp),
    )
    category_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    return get_admin_document_category(conn, category_id), ""


def guess_admin_document_category_name(file_name):
    lowered = file_name.lower()
    if any(token in lowered for token in ("бодлого", "журам", "policy", "procedure")):
        return "Бодлого журам"
    if any(token in lowered for token in ("загвар", "template", "маягт")):
        return "Баримт бичгийн загвар"
    return "Бусад батлагдсан баримт бичиг"


def set_admin_document_category(conn, file_name, category_id):
    timestamp = now_utc().isoformat()
    conn.execute(
        """
        INSERT INTO admin_document_category_links(file_name, category_id, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(file_name) DO UPDATE SET category_id = excluded.category_id, updated_at = excluded.updated_at
        """,
        (file_name, category_id, timestamp, timestamp),
    )


def assigned_admin_document_category(conn, file_name):
    return conn.execute(
        """
        SELECT admin_document_categories.*
        FROM admin_document_category_links
        LEFT JOIN admin_document_categories ON admin_document_categories.id = admin_document_category_links.category_id
        WHERE admin_document_category_links.file_name = ?
        """,
        (file_name,),
    ).fetchone()


def grouped_admin_documents(conn):
    categories = list_admin_document_categories(conn)
    category_by_name = {category["name"]: category for category in categories}
    grouped = {category["id"]: [] for category in categories}
    uncategorized = []
    for doc in list_admin_documents():
        category = assigned_admin_document_category(conn, doc.name)
        if not category:
            category = category_by_name.get(guess_admin_document_category_name(doc.name))
        if category:
            grouped.setdefault(category["id"], []).append((doc, category["id"]))
        else:
            uncategorized.append((doc, None))
    return categories, grouped, uncategorized


def admin_document_category_detail(conn, category_key):
    if category_key is None:
        return None
    decoded = unquote(str(category_key))
    candidate_values = {str(category_key), decoded}
    for value in list(candidate_values):
        try:
            candidate_values.add(value.encode("latin-1").decode("utf-8"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    for value in candidate_values:
        if str(value).isdigit():
            row = conn.execute("SELECT * FROM admin_document_categories WHERE id = ?", (int(value),)).fetchone()
            if row:
                return row
    for value in candidate_values:
        row = conn.execute("SELECT * FROM admin_document_categories WHERE slug = ? OR name = ?", (value, value)).fetchone()
        if row:
            return row
    return None


def rename_admin_document_category(conn, category, name):
    clean_name = normalize_text(name)
    if not clean_name:
        return "Ангиллын нэр оруулна уу."
    existing = conn.execute(
        "SELECT id FROM admin_document_categories WHERE LOWER(name) = LOWER(?) AND id != ?",
        (clean_name, category["id"]),
    ).fetchone()
    if existing:
        return "Ийм нэртэй ангилал аль хэдийн байна."
    conn.execute(
        "UPDATE admin_document_categories SET name = ?, slug = ?, updated_at = ? WHERE id = ?",
        (clean_name, unique_slug(conn, "admin_document_categories", clean_name, ignore_id=category["id"]), now_utc().isoformat(), category["id"]),
    )
    return ""


def delete_admin_document_category(conn, category):
    conn.execute("DELETE FROM admin_document_categories WHERE id = ?", (category["id"],))


def list_documents_for_admin_category(conn, category_id):
    docs = []
    target_category = get_admin_document_category(conn, category_id)
    if not target_category:
        return docs
    for doc in list_admin_documents():
        category = assigned_admin_document_category(conn, doc.name)
        if not category:
            guessed = guess_admin_document_category_name(doc.name)
            if guessed and guessed == target_category["name"]:
                docs.append(doc)
        elif category["id"] == category_id:
            docs.append(doc)
    return docs


def admin_document_category_page(conn, user, category, notice=""):
    docs = list_documents_for_admin_category(conn, category["id"])
    cards = []
    for doc in docs:
        cards.append(
            f"""
            <article class="card">
              <h2>{html.escape(doc.name)}</h2>
              <p class="muted">Төрөл: {html.escape(doc.suffix.lstrip('.') or 'file').upper()}</p>
              <div class="action-strip">
                <a class="button-link" href="/admin-docs/{quote(doc.name)}">Нээж үзэх</a>
                <a class="button-link ghost" href="/admin-docs/{quote(doc.name)}/download">Татах</a>
              </div>
              <form method="post" action="/admin-docs/{quote(doc.name)}/replace" enctype="multipart/form-data" class="stack-form upload-form">
                <input type="hidden" name="return_to" value="/admin-doc-categories/{category['id']}">
                <label>Файл шинэчлэх<input type="file" name="document" required></label>
                <button type="submit">Файл шинэчлэх</button>
              </form>
              <form method="post" action="/admin-docs/{quote(doc.name)}/delete" class="inline-form" onsubmit="return confirm('Энэ файлыг устгах уу?');">
                <input type="hidden" name="return_to" value="/admin-doc-categories/{category['id']}">
                <button type="submit" class="button-link ghost">Файл устгах</button>
              </form>
            </article>
            """
        )
    body = f"""
    <section class="panel">
      <h2>{html.escape(category['name'])}</h2>
      <form method="post" action="/admin-docs/create" enctype="multipart/form-data" class="stack-form upload-form upload-form-panel">
        <input type="hidden" name="category_id" value="{category['id']}">
        <input type="hidden" name="return_to" value="/admin-doc-categories/{category['id']}">
        <label>Шинэ файлын нэр<input type="text" name="filename" placeholder="example.pdf" required></label>
        <label>Файл<input type="file" name="document" required></label>
        <button type="submit">Файл нэмэх</button>
      </form>
      <div class="card-grid">{''.join(cards) if cards else '<p>Одоогоор файл алга.</p>'}</div>
    </section>
    """
    return render_page(category["name"], user, body, notice)


def resolve_admin_document(raw_name):
    decoded_name = unquote(raw_name)
    candidate_names = {raw_name, decoded_name}
    for value in (raw_name, decoded_name):
        try:
            candidate_names.add(value.encode("latin-1").decode("utf-8"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    for doc in list_admin_documents():
        if doc.name in candidate_names or quote(doc.name) in candidate_names:
            return doc.resolve()
    return None


def docx_text_from_node(node):
    return "".join((part.text or "") for part in node.iterfind('.//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t')).strip()


def extract_docx_blocks(file_path):
    try:
        with ZipFile(file_path) as zf:
            root = ET.fromstring(zf.read("word/document.xml"))
    except Exception:
        return []

    body = root.find('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}body')
    if body is None:
        return []

    blocks = []
    for child in list(body):
        tag = child.tag.rsplit('}', 1)[-1]
        if tag == 'p':
            line = docx_text_from_node(child)
            if line:
                blocks.append(("paragraph", line))
        elif tag == 'tbl':
            rows = []
            for row in child.findall('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}tr'):
                cells = []
                for cell in row.findall('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}tc'):
                    cell_lines = []
                    for para in cell.findall('.//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                        value = docx_text_from_node(para)
                        if value:
                            cell_lines.append(value)
                    cells.append("\n".join(cell_lines).strip())
                if any(cells):
                    rows.append(cells)
            if rows:
                blocks.append(("table", rows))
    return blocks


def render_admin_documents_overview(conn):
    categories = list_admin_document_categories(conn)
    rows = []
    for category in categories:
        count = len(list_documents_for_admin_category(conn, category["id"]))
        rows.append(
            f"""
            <tr>
              <td><a class="table-link" href="/admin-doc-categories/{category['id']}">{html.escape(category['name'])}</a></td>
              <td class="table-actions"><span class="muted">{count} файл</span></td>
            </tr>
            """
        )
    manage_rows = []
    for category in categories:
        manage_rows.append(
            f"""
            <tr>
              <td>{html.escape(category['name'])}</td>
              <td>
                <form method="post" action="/admin-doc-categories/{category['id']}/rename" class="inline-rename-form split-rename-form">
                  <input type="text" name="name" value="{html.escape(category['name'])}" class="table-inline-input compact-input" required>
                  <button type="submit" class="button-link ghost small">Нэр өөрчлөх</button>
                </form>
              </td>
              <td class="table-actions">
                <form method="post" action="/admin-doc-categories/{category['id']}/delete" class="inline-form" onsubmit="return confirm('Энэ ангиллыг устгах уу?');">
                  <button type="submit" class="link-button danger">Устгах</button>
                </form>
              </td>
            </tr>
            """
        )
    return f"""
    <section class="panel">
      <div class="heading-row compact-heading-row">
        <div>
          <h2>Админ баримтууд</h2>
          <p class="muted">Ангиллын нэр дээр дарж тухайн ангиллын файлуудыг удирдана.</p>
        </div>
        <button type="button" class="button-link ghost manage-columns-button" onclick="toggleVisibility('admin-doc-category-editor', this)" data-open-label="Ангилал засах" data-close-label="Ангилал засах" aria-expanded="false">Ангилал засах</button>
      </div>
      <div id="admin-doc-category-editor" class="toggle-form manage-columns-panel" hidden>
        <form method="post" action="/admin-doc-categories/create" class="stack-form upload-form compact-manage-form">
          <label>Шинэ ангиллын нэр<input type="text" name="name" placeholder="Жишээ: Ажиллах заавар" required></label>
          <button type="submit">Ангилал нэмэх</button>
        </form>
        <div class="nested-table-wrap table-wrap">
          <table>
            <thead>
              <tr><th>Ангилал</th><th>Нэр өөрчлөх</th><th></th></tr>
            </thead>
            <tbody>{''.join(manage_rows) if manage_rows else '<tr><td colspan="3">Одоогоор ангилал алга.</td></tr>'}</tbody>
          </table>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Нэр</th><th></th></tr>
          </thead>
          <tbody>{''.join(rows) if rows else '<tr><td colspan="2">Одоогоор ангилал алга.</td></tr>'}</tbody>
        </table>
      </div>
    </section>
    """


def admin_document_view_page(conn, user, file_path, notice=""):
    category = assigned_admin_document_category(conn, file_path.name)
    back_href = f"/admin-doc-categories/{category['id']}" if category else "/dashboard"
    blocks = extract_docx_blocks(file_path)
    rendered = []
    for block_type, value in blocks:
        if block_type == "paragraph":
            rendered.append(f"<p>{html.escape(value)}</p>")
            continue
        if block_type == "table":
            row_html = []
            for row_index, row in enumerate(value):
                tag = 'th' if row_index == 0 else 'td'
                cells = ''.join(f'<{tag}>{format_multiline(cell)}</{tag}>' for cell in row)
                row_html.append(f'<tr>{cells}</tr>')
            rendered.append(f'<div class="doc-table-wrap"><table class="doc-table">{"".join(row_html)}</table></div>')
    content = "".join(rendered) or "<p>Энэ баримтын урьдчилан харах агуулгыг уншиж чадсангүй.</p>"
    download_href = f"/admin-docs/{quote(file_path.name)}/download"
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(file_path.name)}</h1>
          <p class="muted">Админ хэрэглэгчид зориулсан баримтын харагдац.</p>
        </div>
        <div class="action-strip">
          <a class="button-link ghost" href="{back_href}">Буцах</a>
          <a class="button-link" href="{download_href}">Татах</a>
        </div>
      </div>
      <section class="doc-viewer">{content}</section>
    </section>
    """
    return render_page(file_path.name, user, body, notice)


def send_file(start_response, file_path):
    guessed_type, _ = mimetypes.guess_type(str(file_path))
    content_type = guessed_type or "application/octet-stream"
    payload = file_path.read_bytes()
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(payload))),
        ("Content-Disposition", f"attachment; filename*=UTF-8''{quote(file_path.name)}"),
    ]
    start_response("200 OK", headers)
    return [payload]


def send_inline_file(start_response, file_path):
    guessed_type, _ = mimetypes.guess_type(str(file_path))
    content_type = guessed_type or "application/octet-stream"
    payload = file_path.read_bytes()
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(payload))),
        ("Content-Disposition", f"inline; filename*=UTF-8''{quote(file_path.name)}"),
    ]
    start_response("200 OK", headers)
    return [payload]


_AUDIT_ACTION_LABELS = {
    "login": ("Нэвтэрсэн", "login"),
    "logout": ("Гарсан", "login"),
    "login_failed": ("Нэвтрэх амжилтгүй", "danger"),
    "first_access": ("Анхны нэвтрэлт", "login"),
    "change_password": ("Нууц үг солилт", "update"),
    "reset_password": ("Нууц үг reset", "update"),
    "create": ("Үүсгэсэн", "create"),
    "update": ("Засварласан", "update"),
    "delete": ("Устгасан", "danger"),
    "update_permissions": ("Эрх өөрчлөлт", "update"),
}
_AUDIT_ENTITY_LABELS = {
    "asset": "Хөрөнгө",
    "user": "Хэрэглэгч",
    "department": "Хэлтэс",
    "admin_document_category": "Баримтын ангилал",
    "admin_document": "Баримт бичиг",
    "custom_register": "Бүртгэл",
    "custom_register_row": "Бүртгэлийн мөр",
    "attachment_disposal": "Устгалтын бүртгэл",
    "attachment_change": "Өөрчлөлтийн бүртгэл",
}


def audit_page(conn, user, notice=""):
    rows = conn.execute(
        """
        SELECT audit_logs.*, actor.username AS actor_username, target.username AS target_username,
               departments.name AS department_name
        FROM audit_logs
        LEFT JOIN users AS actor ON actor.id = audit_logs.actor_user_id
        LEFT JOIN users AS target ON target.id = audit_logs.target_user_id
        LEFT JOIN departments ON departments.id = audit_logs.department_id
        ORDER BY audit_logs.created_at DESC, audit_logs.id DESC
        LIMIT 300
        """
    ).fetchall()
    body_rows = []
    for row in rows:
        action_label, pill_cls = _AUDIT_ACTION_LABELS.get(row["action"], (row["action"], "update"))
        entity_label = _AUDIT_ENTITY_LABELS.get(row["entity_type"], row["entity_type"])
        # Build a compact detail cell: entity label + optional target user + details text
        detail_parts = []
        if row["entity_type"] and row["entity_type"] not in ("", "-"):
            prefix = html.escape(entity_label)
            if row["entity_id"] and row["entity_id"] not in ("", "0"):
                prefix += f' <span class="audit-id">#{html.escape(row["entity_id"])}</span>'
            detail_parts.append(f'<span class="audit-entity">{prefix}</span>')
        if row["target_username"]:
            detail_parts.append(f'→ <strong>{html.escape(row["target_username"])}</strong>')
        if row["details"] and row["details"] not in ("-", ""):
            detail_parts.append(f'<span class="audit-detail-text">{format_multiline(row["details"])}</span>')
        detail_html = "<br>".join(detail_parts) if detail_parts else "-"
        body_rows.append(
            f"""
            <tr>
              <td class="audit-col-time">{format_dt(row['created_at'])}</td>
              <td class="audit-col-actor">{html.escape(row['actor_username'] or 'Систем')}</td>
              <td class="audit-col-action"><span class="audit-pill {pill_cls}">{html.escape(action_label)}</span></td>
              <td class="audit-col-department">{html.escape(row['department_name'] or '—')}</td>
              <td class="audit-col-details">{detail_html}</td>
            </tr>
            """
        )
    body = f"""
    <section class="panel">
      <h1>Аудит лог</h1>
      <p class="muted">Сүүлийн 300 үйлдлийг харуулж байна.</p>
      <div class="table-wrap audit-table-wrap">
        <table class="audit-table">
          <thead>
            <tr>
              <th class="audit-col-time">Огноо</th>
              <th class="audit-col-actor">Хэрэглэгч</th>
              <th class="audit-col-action">Үйлдэл</th>
              <th class="audit-col-department">Хэлтэс</th>
              <th class="audit-col-details">Дэлгэрэнгүй</th>
            </tr>
          </thead>
          <tbody>{''.join(body_rows) if body_rows else '<tr><td colspan="5">Одоогоор аудит лог алга.</td></tr>'}</tbody>
        </table>
      </div>
    </section>
    """
    return render_page("Аудит лог", user, body, notice)


def render_attachment_form(action, register, values, error="", submit_label="Хадгалах"):
    source = dict(values or {})
    inputs = []
    for name, label, required, field_type in register["fields"]:
        value = html.escape(source.get(name, ""))
        required_attr = " required" if required else ""
        if field_type == "textarea":
            field = f'<textarea name="{name}"{required_attr}>{value}</textarea>'
        else:
            field = f'<input type="text" name="{name}" value="{value}"{required_attr}>'
        inputs.append(f"<label>{html.escape(label)}{field}</label>")
    return f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(register['title'])}</h1>
          <p class="muted">{html.escape(register['description'])}</p>
        </div>
        <a class="button-link ghost" href="/admin-docs/registers/{html.escape(register['slug'])}">Жагсаалт руу буцах</a>
      </div>
      {fmt_error(error)}
      <form method="post" action="{action}" class="asset-form">
        {''.join(inputs)}
        <div class="actions"><button type="submit">{submit_label}</button></div>
      </form>
    </section>
    """


def validate_attachment_form(form, register):
    values = {}
    for field_name, label, required, _ in register["fields"]:
        value = normalize_text(form.get(field_name))
        if required and not value:
            return None, f"{label} талбарыг бөглөнө үү."
        values[field_name] = value
    return values, ""


def get_attachment_entry(conn, register, entry_id):
    return conn.execute(f"SELECT * FROM {register['table']} WHERE id = ?", (entry_id,)).fetchone()


def attachment_register_list_page(conn, user, register, notice=""):
    columns = register["list_fields"]
    rows = conn.execute(f"SELECT * FROM {register['table']} ORDER BY id DESC").fetchall()
    body_rows = []
    for row in rows:
        cells = [f"<td>{row['id']}</td>"]
        for field_name, _ in columns:
            cells.append(f"<td>{format_multiline(row[field_name])}</td>")
        cells.append(
            f"""
            <td class="table-actions">
              <div class="action-strip">
                <a class="button-link ghost small" href="/admin-docs/registers/{html.escape(register['slug'])}/{row['id']}">Дэлгэрэнгүй</a>
                <a class="button-link ghost small" href="/admin-docs/registers/{html.escape(register['slug'])}/{row['id']}/edit">Засах</a>
                <form method="post" action="/admin-docs/registers/{html.escape(register['slug'])}/{row['id']}/delete" class="inline-form" onsubmit="return confirm(\'Устгахдаа итгэлтэй байна уу?\')">
                  <button type="submit" class="link-button danger">Устгах</button>
                </form>
              </div>
            </td>
            """
        )
        body_rows.append(f"<tr>{''.join(cells)}</tr>")
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(register['title'])}</h1>
          <p class="muted">{html.escape(register['description'])}</p>
        </div>
        <div class="action-strip">
          <a class="button-link ghost" href="/admin-docs">Буцах</a>
          <a class="button-link" href="/admin-docs/registers/{html.escape(register['slug'])}/new">Мөр нэмэх</a>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>№</th>{''.join(f'<th>{html.escape(label)}</th>' for _, label in columns)}<th></th></tr>
          </thead>
          <tbody>
            {''.join(body_rows) if body_rows else f'<tr><td colspan="{len(columns) + 2}">Одоогоор бүртгэл алга.</td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
    """
    return render_page(register["title"], user, body, notice)


def attachment_register_detail_page(user, register, entry, notice=""):
    items = [f"""
        <article class="detail-item">
          <div class="detail-label">№</div>
          <div class="detail-value">{entry['id']}</div>
        </article>
        """]
    for field_name, label, _, _ in register["fields"]:
        items.append(
            f"""
            <article class="detail-item">
              <div class="detail-label">{html.escape(label)}</div>
              <div class="detail-value">{format_multiline(entry[field_name])}</div>
            </article>
            """
        )
    items.append(
        f"""
        <article class="detail-item">
          <div class="detail-label">Сүүлд өөрчилсөн</div>
          <div class="detail-value">{format_dt(entry['updated_at'])}</div>
        </article>
        """
    )
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(register['title'])}</h1>
          <p class="muted">Бүртгэлийн мөрийн дэлгэрэнгүй мэдээлэл.</p>
        </div>
        <div class="action-strip">
          <a class="button-link ghost" href="/admin-docs/registers/{html.escape(register['slug'])}">Буцах</a>
          <a class="button-link ghost" href="/admin-docs/registers/{html.escape(register['slug'])}/{entry['id']}/edit">Засах</a>
        </div>
      </div>
      <div class="detail-grid">{''.join(items)}</div>
    </section>
    """
    return render_page(register["title"], user, body, notice)


def validate_asset_form(form, user, permissions, existing_asset=None):
    values = {}
    for field, label, required in ASSET_FIELDS:
        editable = can_edit_field(user, permissions, field)
        if editable:
            value = normalize_text(form.get(field))
            if field in {"has_personal_data", "has_sensitive_data"}:
                value = normalize_flag(value)
        else:
            value = normalize_text((existing_asset or {}).get(field))
        if required and editable and not value:
            return None, f"{label} талбарыг бөглөнө үү."
        values[field] = value
    # review_frequency: admin-only editable
    if user["is_admin"]:
        freq = normalize_text(form.get("review_frequency"))
        values["review_frequency"] = freq if freq in FREQUENCY_OPTIONS else ""
    else:
        values["review_frequency"] = normalize_text((existing_asset or {}).get("review_frequency", ""))
    return values, ""


def get_department(conn, slug):
    return conn.execute("SELECT * FROM departments WHERE slug = ?", (slug,)).fetchone()


def get_asset(conn, asset_id, department_id):
    return conn.execute("SELECT * FROM assets WHERE id = ? AND department_id = ?", (asset_id, department_id)).fetchone()


def get_user_with_department(conn, user_id):
    return conn.execute(
        """
        SELECT users.*, departments.name AS department_name
        FROM users
        LEFT JOIN departments ON departments.id = users.department_id
        WHERE users.id = ?
        """,
        (user_id,),
    ).fetchone()


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()
    query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
    conn = get_db()
    user = get_current_user(environ, conn)

    if path == "/static/styles.css":
        css = (BASE_DIR / "static" / "styles.css").read_text(encoding="utf-8")
        payload = css.encode("utf-8")
        start_response("200 OK", [("Content-Type", "text/css; charset=utf-8"), ("Content-Length", str(len(payload)))])
        conn.close()
        return [payload]

    if path == "/static/dico_logo.png":
        logo_path = BASE_DIR / "dico_logo.png"
        payload = logo_path.read_bytes()
        start_response("200 OK", [("Content-Type", "image/png"), ("Content-Length", str(len(payload)))])
        conn.close()
        return [payload]

    if path == "/favicon.ico":
        conn.close()
        start_response("204 No Content", [("Content-Length", "0")])
        return [b""]

    if path == "/":
        conn.close()
        return redirect(start_response, "/dashboard" if user else "/login")

    if path == "/login":
        if method == "GET":
            page = login_form(notice=qs_value(query, "notice"), username=qs_value(query, "username"))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        username = normalize_text(form.get("username"))
        candidate = conn.execute(
            """
            SELECT users.*, departments.slug AS department_slug, departments.name AS department_name
            FROM users
            LEFT JOIN departments ON departments.id = users.department_id
            WHERE username = ? AND is_active = 1
            """,
            (username,),
        ).fetchone()
        if candidate and not candidate["is_admin"] and not candidate["password_hash"]:
            conn.close()
            return redirect(start_response, "/first-access?username=" + quote(username) + "&notice=" + quote("Энэ хэрэглэгч анхны нэвтрэхдээ нууц үгээ үүсгэнэ."))
        if not candidate or not verify_password(form.get("password", ""), candidate["password_hash"]):
            attempted_username = username or "(хоосон)"
            record_audit(
                conn,
                candidate["id"] if candidate else None,
                "failed_login",
                "session",
                department_id=candidate["department_id"] if candidate else None,
                details=f"Амжилтгүй нэвтрэх оролдлого: {attempted_username}",
                target_user_id=candidate["id"] if candidate else None,
            )
            conn.commit()
            page = login_form(error="Хэрэглэгчийн нэр эсвэл нууц үг буруу байна.", username=username)
            conn.close()
            return response(start_response, "401 Unauthorized", page)
        session_id = create_session(conn, candidate["id"])
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_utc().isoformat(), candidate["id"]))
        record_audit(conn, candidate["id"], "login", "session", entity_id=session_id, department_id=candidate["department_id"], details="Хэрэглэгч системд нэвтэрлээ.")
        conn.commit()
        destination = "/account/password?notice=" + quote("Нэг удаагийн нууц үгээ баталгаажуулаад шинэ нууц үг үүсгэнэ үү.") if candidate["must_change_password"] else "/dashboard"
        conn.close()
        return redirect(start_response, destination, headers=[session_cookie_header(session_id)])

    if path == "/first-access":
        if method == "GET":
            page = first_access_page(notice=qs_value(query, "notice"), username=qs_value(query, "username"))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        username = normalize_text(form.get("username"))
        candidate = conn.execute(
            """
            SELECT users.*, departments.slug AS department_slug, departments.name AS department_name
            FROM users
            LEFT JOIN departments ON departments.id = users.department_id
            WHERE username = ? AND is_active = 1 AND is_admin = 0
            """,
            (username,),
        ).fetchone()
        if not candidate or candidate["password_hash"]:
            page = first_access_page(error="Энэ хэрэглэгч анхны тохиргооны төлөвт байхгүй байна.", username=username)
            conn.close()
            return response(start_response, "400 Bad Request", page)
        if form.get("new_password", "") != form.get("confirm_password", ""):
            page = first_access_page(error="Шинэ нууц үг таарахгүй байна.", username=username)
            conn.close()
            return response(start_response, "400 Bad Request", page)
        policy_error = validate_password_policy(form.get("new_password", ""))
        if policy_error:
            page = first_access_page(error=policy_error, username=username)
            conn.close()
            return response(start_response, "400 Bad Request", page)
        timestamp = now_utc().isoformat()
        conn.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = ?, last_login_at = ?, must_change_password = 0 WHERE id = ?",
            (hash_password(form.get("new_password", "")), timestamp, timestamp, candidate["id"]),
        )
        session_id = create_session(conn, candidate["id"])
        record_audit(conn, candidate["id"], "first_password_set", "user", entity_id=candidate["id"], department_id=candidate["department_id"], target_user_id=candidate["id"], details="Хэрэглэгч анхны нууц үгээ үүсгэлээ.")
        record_audit(conn, candidate["id"], "login", "session", entity_id=session_id, department_id=candidate["department_id"], details="Хэрэглэгч анхны тохиргооны дараа нэвтэрлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/dashboard", headers=[session_cookie_header(session_id)])

    if not user:
        conn.close()
        return redirect(start_response, "/login?notice=" + quote("Эхлээд нэвтэрнэ үү."))

    if path == "/logout" and method == "POST":
        record_audit(conn, user["id"], "logout", "session", entity_id=user["session_id"], department_id=user["department_id"], details="Хэрэглэгч системээс гарлаа.")
        clear_session(conn, environ)
        conn.commit()
        conn.close()
        return redirect(start_response, "/login?notice=" + quote("Системээс гарлаа."), headers=[session_cookie_header("expired", 0)])

    if password_setup_required(user) and path != "/account/password":
        conn.close()
        return redirect(start_response, "/account/password?notice=" + quote("Нэг удаагийн нууц үгээ оруулж шинэ нууц үгээ үүсгэх хүртэл системийн бусад хэсэгт хандах боломжгүй."))

    if path == "/dashboard":
        page = dashboard_page(conn, user, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/departments":
        page = departments_page(conn, user, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/review-timer/reset":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if method != "POST":
            conn.close()
            return redirect(start_response, "/dashboard")
        deadline = now_utc() + dt.timedelta(days=REVIEW_INTERVAL_DAYS)
        set_setting(conn, REVIEW_TIMER_KEY, deadline.isoformat())
        record_audit(conn, user["id"], "reset_review_timer", "setting", entity_id=REVIEW_TIMER_KEY, details=f"Хөрөнгийн хяналтын таймерыг {REVIEW_INTERVAL_DAYS} хоногоор дахин эхлүүлэв.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/dashboard?notice=" + quote("Хөрөнгийн хяналтын таймер дахин эхэллээ."))


    if path == "/custom-registers/create":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if method != "POST":
            conn.close()
            return redirect(start_response, "/dashboard")
        form = parse_post(environ)
        register, error = create_custom_register(conn, form.get("title"), form.get("description"))
        if error:
            conn.close()
            return redirect(start_response, "/dashboard?notice=" + quote(error))
        record_audit(conn, user["id"], "create", "custom_register", entity_id=register["id"], details=f"{register['title']} бүртгэл үүсгэлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote("Бүртгэл амжилттай үүслээ."))

    if path.startswith("/custom-registers/"):
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        parts = [unquote(part) for part in path.strip("/").split("/")]
        if len(parts) < 2:
            conn.close()
            return not_found(start_response)
        register = get_custom_register(conn, parts[1])
        if not register:
            conn.close()
            return not_found(start_response)
        if len(parts) == 2 and method == "GET":
            page = custom_register_detail_page(conn, user, register, qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        if len(parts) == 3 and parts[2] == "delete" and method == "POST":
            conn.execute("DELETE FROM custom_registers WHERE id = ?", (register["id"],))
            record_audit(conn, user["id"], "delete", "custom_register", entity_id=register["id"], details=f"{register['title']} бүртгэл устгалаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/dashboard?notice=" + quote("Бүртгэл устгагдлаа."))
        if len(parts) == 3 and parts[2] == "rename" and method == "POST":
            form = parse_post(environ)
            error = rename_custom_register(conn, register, form.get("title"))
            if error:
                conn.close()
                return redirect(start_response, "/dashboard?notice=" + quote(error))
            record_audit(conn, user["id"], "update", "custom_register", entity_id=register["id"], details=f"{register['title']} бүртгэлийн нэр шинэчлэгдлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/dashboard?notice=" + quote("Бүртгэлийн нэр шинэчлэгдлээ."))
        if len(parts) == 4 and parts[2] == "columns" and parts[3] == "create" and method == "POST":
            form = parse_post(environ)
            column, error = create_custom_register_column(conn, register, form.get("name"))
            if error:
                conn.close()
                return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote(error))
            record_audit(conn, user["id"], "create", "custom_register_column", entity_id=column["id"], details=f"{register['title']} бүртгэлд {column['name']} багана нэмлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote("Багана нэмэгдлээ."))
        if len(parts) == 5 and parts[2] == "columns" and parts[4] == "rename" and method == "POST":
            form = parse_post(environ)
            error = rename_custom_register_column(conn, register, parts[3], form.get("name"))
            if error:
                conn.close()
                return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote(error))
            record_audit(conn, user["id"], "update", "custom_register_column", entity_id=parts[3], details=f"{register['title']} бүртгэлийн баганын нэрийг шинэчиллээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote("Баганын нэр шинэчлэгдлээ."))
        if len(parts) == 5 and parts[2] == "columns" and parts[4] == "delete" and method == "POST":
            column = conn.execute("SELECT * FROM custom_register_columns WHERE id = ? AND register_id = ?", (parts[3], register["id"])).fetchone()
            if not column:
                conn.close()
                return not_found(start_response)
            conn.execute("DELETE FROM custom_register_columns WHERE id = ?", (column["id"],))
            record_audit(conn, user["id"], "delete", "custom_register_column", entity_id=column["id"], details=f"{register['title']} бүртгэлээс {column['name']} багана устгалаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote("Багана устгагдлаа."))
        if len(parts) == 4 and parts[2] == "rows" and parts[3] == "new":
            columns = list_custom_register_columns(conn, register["id"])
            if method == "GET":
                page = custom_register_row_form_page(user, register, columns, action_path=f"/custom-registers/{quote(register['slug'])}/rows/new")
                conn.close()
                return response(start_response, "200 OK", page)
            values = validate_custom_register_row_form(parse_post(environ), columns)
            row_id = save_custom_register_row(conn, register, values)
            record_audit(conn, user["id"], "create", "custom_register_row", entity_id=row_id, details=f"{register['title']} бүртгэлд мөр нэмлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote("Мөр нэмэгдлээ."))
        if len(parts) == 5 and parts[2] == "rows" and parts[4] == "edit":
            row = get_custom_register_row(conn, register["id"], parts[3])
            if not row:
                conn.close()
                return not_found(start_response)
            columns = list_custom_register_columns(conn, register["id"])
            if method == "GET":
                page = custom_register_row_form_page(user, register, columns, values=get_custom_row_values(conn, row["id"]), submit_label="Өөрчлөлт хадгалах", action_path=f"/custom-registers/{quote(register['slug'])}/rows/{row['id']}/edit")
                conn.close()
                return response(start_response, "200 OK", page)
            values = validate_custom_register_row_form(parse_post(environ), columns)
            save_custom_register_row(conn, register, values, row=row)
            record_audit(conn, user["id"], "update", "custom_register_row", entity_id=row["id"], details=f"{register['title']} бүртгэлийн мөр шинэчлэгдлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote("Мөр шинэчлэгдлээ."))
        if len(parts) == 5 and parts[2] == "rows" and parts[4] == "delete" and method == "POST":
            row = get_custom_register_row(conn, register["id"], parts[3])
            if not row:
                conn.close()
                return not_found(start_response)
            conn.execute("DELETE FROM custom_register_rows WHERE id = ?", (row["id"],))
            record_audit(conn, user["id"], "delete", "custom_register_row", entity_id=row["id"], details=f"{register['title']} бүртгэлийн мөр устгагдлаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/custom-registers/{quote(register['slug'])}?notice=" + quote("Мөр устгагдлаа."))
        if len(parts) == 3 and parts[2] in {"export.xlsx", "export.pdf"} and method == "GET":
            matrix, export_lines = custom_register_export_matrix(conn, register)
            action = "download_excel" if parts[2].endswith("xlsx") else "download_pdf"
            entity_type = "custom_register"
            record_audit(conn, user["id"], action, entity_type, entity_id=register["id"], details=f"{register['title']} бүртгэлийг {parts[2].split('.')[-1].upper()} файлаар татлаа.")
            conn.commit()
            conn.close()
            if parts[2].endswith("xlsx"):
                payload = build_xlsx_payload(register["title"], matrix)
                return send_bytes(start_response, payload, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", custom_register_export_filename(register, "xlsx"))
            payload = build_pdf_payload(register["title"], export_lines)
            return send_bytes(start_response, payload, "application/pdf", custom_register_export_filename(register, "pdf"))
        conn.close()
        return not_found(start_response)

    if path == "/account/password":
        if method == "GET":
            page = password_change_page(user, notice=qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        if not verify_password(form.get("current_password", ""), user["password_hash"]):
            page = password_change_page(user, error="Одоогийн нууц үг буруу байна.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        if form.get("new_password", "") != form.get("confirm_password", ""):
            page = password_change_page(user, error="Шинэ нууц үг таарахгүй байна.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        policy_error = validate_password_policy(form.get("new_password", ""))
        if policy_error:
            page = password_change_page(user, error=policy_error)
            conn.close()
            return response(start_response, "400 Bad Request", page)
        timestamp = now_utc().isoformat()
        was_forced_password_change = bool(user["must_change_password"])
        conn.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = ?, must_change_password = 0 WHERE id = ?",
            (hash_password(form.get("new_password", "")), timestamp, user["id"]),
        )
        record_audit(conn, user["id"], "change_password", "user", entity_id=user["id"], department_id=user["department_id"], target_user_id=user["id"], details="Хэрэглэгч өөрийн нууц үгийг сольсон.")
        conn.commit()
        conn.close()
        destination = "/dashboard?notice=" + quote("Нууц үг амжилттай солигдлоо.") if was_forced_password_change else "/account/password?notice=" + quote("Нууц үг амжилттай солигдлоо.")
        return redirect(start_response, destination)

    if path == "/users":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if method != "GET":
            page = users_page(conn, user, error="Энэ хэсэгт зөвхөн нууц үг reset хийх боломжтой.")
            conn.close()
            return response(start_response, "405 Method Not Allowed", page)
        page = users_page(conn, user, notice=qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)
    if path == "/permissions":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if method == "GET":
            page = permissions_page(conn, user, notice=qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        timestamp = now_utc().isoformat()
        for department in conn.execute("SELECT * FROM departments"):
            enabled = []
            disabled = []
            for field_name, label, _ in ASSET_FIELDS:
                checkbox = f"perm__{department['id']}__{field_name}"
                can_edit = 1 if form.get(checkbox) == "1" else 0
                conn.execute(
                    "UPDATE department_column_permissions SET can_edit = ?, updated_at = ? WHERE department_id = ? AND field_name = ?",
                    (can_edit, timestamp, department["id"], field_name),
                )
                (enabled if can_edit else disabled).append(label)
            details = f"Идэвхтэй: {', '.join(enabled) if enabled else '-'} | Хаалттай: {', '.join(disabled) if disabled else '-'}"
            record_audit(conn, user["id"], "update_permissions", "department", entity_id=department["id"], department_id=department["id"], details=details)
        conn.commit()
        conn.close()
        return redirect(start_response, "/permissions?notice=" + quote("Багануудын засах эрх шинэчлэгдлээ."))

    if path == "/admin-docs":
        conn.close()
        return redirect(start_response, "/dashboard?notice=" + quote("Админ баримтууд хэсгийг хяналтын таймерын доор шилжүүллээ."))

    if path == "/admin-doc-categories/create":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if method != "POST":
            conn.close()
            return redirect(start_response, "/dashboard")
        form = parse_post(environ)
        category, error = create_admin_document_category(conn, form.get("name"))
        if error:
            conn.close()
            return redirect(start_response, "/dashboard?notice=" + quote(error))
        record_audit(conn, user["id"], "create", "admin_document_category", entity_id=category["id"], details=f"{category['name']} ангилал нэмлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/dashboard?notice=" + quote("Баримтын ангилал нэмэгдлээ."))

    if path.startswith("/admin-docs/registers/"):
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        parts = [unquote(part) for part in path.strip("/").split("/")]
        if len(parts) < 3:
            conn.close()
            return not_found(start_response)
        register = get_attachment_register(parts[2])
        if not register:
            conn.close()
            return not_found(start_response)

        if len(parts) == 3 and method == "GET":
            page = attachment_register_list_page(conn, user, register, qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)

        if len(parts) == 4 and parts[3] == "new":
            if method == "GET":
                page = render_page(register["title"], user, render_attachment_form(path, register, {}))
                conn.close()
                return response(start_response, "200 OK", page)
            form = parse_post(environ)
            values, error = validate_attachment_form(form, register)
            if error:
                page = render_page(register["title"], user, render_attachment_form(path, register, form, error=error))
                conn.close()
                return response(start_response, "400 Bad Request", page)
            timestamp = now_utc().isoformat()
            columns = [field_name for field_name, _, _, _ in register["fields"]] + ["created_at", "updated_at"]
            placeholders = ", ".join(["?"] * len(columns))
            conn.execute(
                f"INSERT INTO {register['table']} ({', '.join(columns)}) VALUES ({placeholders})",
                [values[field_name] for field_name, _, _, _ in register["fields"]] + [timestamp, timestamp],
            )
            entry_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            record_audit(conn, user["id"], "create", register["entity_type"], entity_id=entry_id, details=f"{register['title']} бүртгэлд мөр нэмлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/admin-docs/registers/{register['slug']}?notice=" + quote("Бүртгэл амжилттай нэмэгдлээ."))

        if len(parts) == 4 and method == "GET":
            entry = get_attachment_entry(conn, register, parts[3])
            if not entry:
                conn.close()
                return not_found(start_response)
            page = attachment_register_detail_page(user, register, entry, qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)

        if len(parts) == 5 and parts[4] == "edit":
            entry = get_attachment_entry(conn, register, parts[3])
            if not entry:
                conn.close()
                return not_found(start_response)
            if method == "GET":
                page = render_page(register["title"], user, render_attachment_form(path, register, entry, submit_label="Өөрчлөлт хадгалах"))
                conn.close()
                return response(start_response, "200 OK", page)
            form = parse_post(environ)
            values, error = validate_attachment_form(form, register)
            if error:
                page = render_page(register["title"], user, render_attachment_form(path, register, form, error=error, submit_label="Өөрчлөлт хадгалах"))
                conn.close()
                return response(start_response, "400 Bad Request", page)
            values["updated_at"] = now_utc().isoformat()
            values["id"] = entry["id"]
            assignments = ", ".join(f"{field_name} = :{field_name}" for field_name, _, _, _ in register["fields"])
            conn.execute(
                f"UPDATE {register['table']} SET {assignments}, updated_at = :updated_at WHERE id = :id",
                values,
            )
            record_audit(conn, user["id"], "update", register["entity_type"], entity_id=entry["id"], details=f"{register['title']} бүртгэлийн мөр шинэчлэгдлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/admin-docs/registers/{register['slug']}?notice=" + quote("Бүртгэл шинэчлэгдлээ."))

        if len(parts) == 5 and parts[4] == "delete" and method == "POST":
            entry = get_attachment_entry(conn, register, parts[3])
            if not entry:
                conn.close()
                return not_found(start_response)
            conn.execute(f"DELETE FROM {register['table']} WHERE id = ?", (parts[3],))
            record_audit(conn, user["id"], "delete", register["entity_type"], entity_id=parts[3], details=f"{register['title']} бүртгэлийн мөр устгагдлаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/admin-docs/registers/{register['slug']}?notice=" + quote("Бүртгэл устгагдлаа."))

        conn.close()
        return not_found(start_response)

    if path.startswith("/admin-doc-categories/"):
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        parts = [unquote(part) for part in path.strip("/").split("/")]
        if len(parts) < 2:
            conn.close()
            return not_found(start_response)
        category = admin_document_category_detail(conn, parts[1])
        if not category:
            conn.close()
            return not_found(start_response)
        if len(parts) == 2 and method == "GET":
            page = admin_document_category_page(conn, user, category, qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        if len(parts) == 3 and parts[2] == "rename" and method == "POST":
            form = parse_post(environ)
            error = rename_admin_document_category(conn, category, form.get("name"))
            if error:
                conn.close()
                return redirect(start_response, "/dashboard?notice=" + quote(error))
            updated = admin_document_category_detail(conn, category["id"])
            record_audit(conn, user["id"], "update", "admin_document_category", entity_id=category["id"], details=f"{category['name']} ангиллын нэрийг шинэчиллээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/dashboard?notice=" + quote("Ангиллын нэр шинэчлэгдлээ."))
        if len(parts) == 3 and parts[2] == "delete" and method == "POST":
            conn.execute("DELETE FROM admin_document_category_links WHERE category_id = ?", (category["id"],))
            delete_admin_document_category(conn, category)
            record_audit(conn, user["id"], "delete", "admin_document_category", entity_id=category["id"], details=f"{category['name']} ангиллыг устгалаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/dashboard?notice=" + quote("Ангилал устгагдлаа."))
        conn.close()
        return not_found(start_response)

    if path == "/admin-docs/create":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if method != "POST":
            conn.close()
            return redirect(start_response, "/dashboard")
        form = parse_multipart(environ)
        filename = normalize_text(form.getfirst("filename", ""))
        category_id = normalize_text(form.getfirst("category_id", ""))
        return_to = normalize_text(form.getfirst("return_to", "")) or "/dashboard"
        upload = form["document"] if "document" in form else None
        if not filename or not upload or not getattr(upload, "filename", "") or not category_id:
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Файлын нэр, ангилал болон файл оруулна уу."))
        category = get_admin_document_category(conn, category_id)
        if not category:
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Сонгосон ангилал олдсонгүй."))
        safe_name = Path(filename).name
        suffix = Path(safe_name).suffix.lower()
        if suffix not in allowed_admin_document_suffixes():
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Зөвшөөрөгдсөн файл биш байна."))
        target_path = (DOCS_DIR / safe_name).resolve()
        try:
            target_path.relative_to(DOCS_DIR.resolve())
        except ValueError:
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Файлын нэр буруу байна."))
        if target_path.exists():
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Ийм нэртэй файл аль хэдийн байна."))
        payload = upload.file.read()
        if not payload:
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Хоосон файл оруулах боломжгүй."))
        target_path.write_bytes(payload)
        set_admin_document_category(conn, safe_name, category["id"])
        record_audit(conn, user["id"], "create", "admin_document", entity_id=safe_name, details=f"{safe_name} файлыг {category['name']} ангилалд нэмлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, return_to + "?notice=" + quote("Админ файл нэмэгдлээ."))

    if path.startswith("/admin-docs/"):
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        suffix = path.split("/admin-docs/", 1)[1]
        is_download = suffix.endswith("/download")
        is_replace = suffix.endswith("/replace")
        is_delete = suffix.endswith("/delete")
        is_category = suffix.endswith("/category")
        raw_name = suffix[:-9] if is_download else suffix[:-8] if is_replace else suffix[:-7] if is_delete else suffix[:-9] if is_category else suffix
        file_path = resolve_admin_document(raw_name)
        if not file_path:
            conn.close()
            return not_found(start_response)
        try:
            file_path.relative_to(DOCS_DIR.resolve())
        except ValueError:
            conn.close()
            return forbidden(start_response)
        if is_delete:
            if method != "POST":
                conn.close()
                return redirect(start_response, "/dashboard")
            form = parse_post(environ)
            return_to = form.get("return_to") or "/dashboard"
            file_name = file_path.name
            file_path.unlink(missing_ok=False)
            conn.execute("DELETE FROM admin_document_category_links WHERE file_name = ?", (file_name,))
            record_audit(conn, user["id"], "delete", "admin_document", entity_id=file_name, details=f"{file_name} файлыг устгалаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Админ файл устгагдлаа."))
        if is_category:
            if method != "POST":
                conn.close()
                return redirect(start_response, "/dashboard")
            form = parse_post(environ)
            category = get_admin_document_category(conn, form.get("category_id"))
            if not category:
                conn.close()
                return redirect(start_response, "/dashboard?notice=" + quote("Сонгосон ангилал олдсонгүй."))
            set_admin_document_category(conn, file_path.name, category["id"])
            record_audit(conn, user["id"], "update", "admin_document", entity_id=file_path.name, details=f"{file_path.name} файлын ангиллыг {category['name']} болголоо.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/dashboard?notice=" + quote("Файлын ангилал шинэчлэгдлээ."))
        if is_replace:
            if method != "POST":
                conn.close()
                return redirect(start_response, "/dashboard")
            form = parse_multipart(environ)
            return_to = normalize_text(form.getfirst("return_to", "")) or "/dashboard"
            upload = form["document"] if "document" in form else None
            if not upload or not getattr(upload, "filename", ""):
                conn.close()
                return redirect(start_response, return_to + "?notice=" + quote("Файл сонгоно уу."))
            uploaded_name = str(upload.filename)
            if Path(uploaded_name).suffix.lower() != file_path.suffix.lower():
                conn.close()
                return redirect(start_response, return_to + "?notice=" + quote("Ижил төрлийн файл оруулна уу."))
            payload = upload.file.read()
            if not payload:
                conn.close()
                return redirect(start_response, return_to + "?notice=" + quote("Хоосон файл оруулах боломжгүй."))
            file_path.write_bytes(payload)
            record_audit(conn, user["id"], "update", "admin_document", entity_id=file_path.name, details=f"{file_path.name} файлыг шинэчиллээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Админ файл шинэчлэгдлээ."))
        if is_download:
            record_audit(conn, user["id"], "download", "admin_document", entity_id=file_path.name, details=f"{file_path.name} баримтыг татлаа.")
            conn.commit()
            conn.close()
            return send_file(start_response, file_path)
        page = admin_document_view_page(conn, user, file_path, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/reference-docs/create":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if method != "POST":
            conn.close()
            return redirect(start_response, "/departments")
        form = parse_multipart(environ)
        filename = normalize_text(form.getfirst("filename", ""))
        upload = form["document"] if "document" in form else None
        if not filename or not upload or not getattr(upload, "filename", ""):
            conn.close()
            return redirect(start_response, "/departments?notice=" + quote("PDF нэр болон файл оруулна уу."))
        if not filename.lower().endswith(".pdf"):
            filename += ".pdf"
        safe_name = Path(filename).name
        target_path = (STATIC_DIR / safe_name).resolve()
        try:
            target_path.relative_to(STATIC_DIR.resolve())
        except ValueError:
            conn.close()
            return redirect(start_response, "/departments?notice=" + quote("PDF файлын нэр буруу байна."))
        if target_path.exists():
            conn.close()
            return redirect(start_response, "/departments?notice=" + quote("Ийм нэртэй PDF файл аль хэдийн байна."))
        payload = upload.file.read()
        if not payload.startswith(b"%PDF"):
            conn.close()
            return redirect(start_response, "/departments?notice=" + quote("Оруулсан файл PDF биш байна."))
        target_path.write_bytes(payload)
        record_audit(conn, user["id"], "create", "reference_document", entity_id=safe_name, details=f"{safe_name} PDF файлыг нэмлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/departments?notice=" + quote("PDF баримт нэмэгдлээ."))

    if path.startswith("/reference-docs/"):
        suffix = path.split("/reference-docs/", 1)[1]
        is_download = suffix.endswith("/download")
        is_raw = suffix.endswith("/raw")
        is_replace = suffix.endswith("/replace")
        is_delete = suffix.endswith("/delete")
        raw_name = suffix[:-9] if is_download else suffix[:-4] if is_raw else suffix[:-8] if is_replace else suffix[:-7] if is_delete else suffix
        file_path = resolve_reference_document(raw_name)
        if not file_path:
            conn.close()
            return not_found(start_response)
        try:
            file_path.relative_to(STATIC_DIR.resolve())
        except ValueError:
            conn.close()
            return forbidden(start_response)
        if is_delete:
            if not user["is_admin"]:
                conn.close()
                return forbidden(start_response)
            if method != "POST":
                conn.close()
                return redirect(start_response, "/departments")
            file_name = file_path.name
            file_path.unlink(missing_ok=False)
            record_audit(conn, user["id"], "delete", "reference_document", entity_id=file_name, details=f"{file_name} PDF файлыг устгалаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/departments?notice=" + quote("PDF баримт устгагдлаа."))
        if is_replace:
            if not user["is_admin"]:
                conn.close()
                return forbidden(start_response)
            if method != "POST":
                conn.close()
                return redirect(start_response, "/departments")
            form = parse_multipart(environ)
            upload = form["document"] if "document" in form else None
            if not upload or not getattr(upload, "filename", ""):
                conn.close()
                return redirect(start_response, "/departments?notice=" + quote("PDF файл сонгоно уу."))
            if not str(upload.filename).lower().endswith(".pdf"):
                conn.close()
                return redirect(start_response, "/departments?notice=" + quote("Зөвхөн PDF файл оруулна уу."))
            payload = upload.file.read()
            if not payload.startswith(b"%PDF"):
                conn.close()
                return redirect(start_response, "/departments?notice=" + quote("Оруулсан файл PDF биш байна."))
            file_path.write_bytes(payload)
            record_audit(conn, user["id"], "update", "reference_document", entity_id=file_path.name, details=f"{file_path.name} PDF файлыг шинэчиллээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/departments?notice=" + quote("PDF баримт шинэчлэгдлээ."))
        if is_download:
            record_audit(conn, user["id"], "download", "reference_document", entity_id=file_path.name, details=f"{file_path.name} PDF файлыг татлаа.")
            conn.commit()
            conn.close()
            return send_file(start_response, file_path)
        if is_raw:
            conn.close()
            return send_inline_file(start_response, file_path)
        page = reference_document_view_page(user, file_path, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/audit":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        page = audit_page(conn, user, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path.startswith("/users/") and path.endswith("/reset-password"):
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        user_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, user_id)
        if not target_user:
            conn.close()
            return not_found(start_response)
        if method == "GET":
            page = reset_password_page(user, target_user, notice=qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        temp_password = generate_temporary_password()
        conn.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = NULL, must_change_password = 1 WHERE id = ?",
            (hash_password(temp_password), user_id),
        )
        record_audit(conn, user["id"], "reset_password", "user", entity_id=user_id, department_id=target_user["department_id"], target_user_id=user_id, details=f"{target_user['username']} хэрэглэгчийн нууц үгийг админ reset хийлээ.")
        conn.commit()
        page = reset_password_page(user, target_user, notice="Түр нууц үг амжилттай үүслээ.", temp_password=temp_password)
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/users/create":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        all_departments = list(conn.execute("SELECT * FROM departments ORDER BY name"))
        if method == "GET":
            page = render_page("Хэрэглэгч нэмэх", user, user_create_page(all_departments))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        username = (form.get("username") or "").strip()
        dept_id = form.get("department_id") or None
        is_admin = 1 if form.get("is_admin") == "1" else 0
        if not username:
            page = render_page("Хэрэглэгч нэмэх", user, user_create_page(all_departments, error="Хэрэглэгчийн нэр оруулна уу.", values=form))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            page = render_page("Хэрэглэгч нэмэх", user, user_create_page(all_departments, error="Тэрхүү нэртэй хэрэглэгч аль хэдийн байна.", values=form))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        if dept_id:
            dept_row = conn.execute("SELECT id FROM departments WHERE id = ?", (dept_id,)).fetchone()
            dept_id = dept_row["id"] if dept_row else None
        timestamp = now_utc().isoformat()
        conn.execute(
            "INSERT INTO users(username, password_hash, department_id, is_admin, is_active, created_at, must_change_password) VALUES (?, ?, ?, ?, 1, ?, 0)",
            (username, "", dept_id, is_admin, timestamp),
        )
        new_user_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        if dept_id and not is_admin:
            conn.execute(
                "INSERT OR IGNORE INTO user_department_permissions(user_id, department_id, can_read, can_update, created_at, updated_at) VALUES (?, ?, 1, 1, ?, ?)",
                (new_user_id, dept_id, timestamp, timestamp),
            )
        record_audit(conn, user["id"], "create", "user", entity_id=new_user_id, target_user_id=new_user_id, details=f"{username} хэрэглэгч үүслээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, f"/users/{new_user_id}/reset-password?notice=" + quote(f"{username} хэрэглэгч үүслээ. OTP үүсгэн мэдэгдэнэ үү."))

    if path.startswith("/users/") and path.endswith("/edit"):
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        target_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, target_id)
        if not target_user:
            conn.close()
            return not_found(start_response)
        all_departments = list(conn.execute("SELECT * FROM departments ORDER BY name"))
        dept_perms = get_user_dept_perms(conn, target_user["id"])
        if method == "GET":
            page = render_page(f"{target_user['username']} — Засах", user, user_edit_page(conn, target_user, all_departments, dept_perms))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        username = (form.get("username") or "").strip()
        dept_id = form.get("department_id") or None
        is_admin = 1 if form.get("is_admin") == "1" else 0
        is_active = 1 if form.get("is_active") == "1" else 0
        if not username:
            page = render_page(f"{target_user['username']} — Засах", user, user_edit_page(conn, target_user, all_departments, dept_perms, error="Хэрэглэгчийн нэр оруулна уу."))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        clash = conn.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, target_user["id"])).fetchone()
        if clash:
            page = render_page(f"{target_user['username']} — Засах", user, user_edit_page(conn, target_user, all_departments, dept_perms, error="Тэрхүү нэртэй хэрэглэгч аль хэдийн байна."))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        if dept_id:
            dept_row = conn.execute("SELECT id FROM departments WHERE id = ?", (dept_id,)).fetchone()
            dept_id = dept_row["id"] if dept_row else None
        # prevent locking yourself out
        if target_user["id"] == user["id"]:
            is_admin = 1
            is_active = 1
        timestamp = now_utc().isoformat()
        conn.execute(
            "UPDATE users SET username = ?, department_id = ?, is_admin = ?, is_active = ? WHERE id = ?",
            (username, dept_id, is_admin, is_active, target_user["id"]),
        )
        # save department permissions from the matrix
        new_perms = {}
        for d in all_departments:
            new_perms[d["id"]] = {
                "can_read": form.get(f"read_{d['id']}") == "1",
                "can_update": form.get(f"update_{d['id']}") == "1",
            }
        save_user_dept_perms(conn, target_user["id"], new_perms)
        record_audit(conn, user["id"], "update", "user", entity_id=target_user["id"], target_user_id=target_user["id"], details=f"{username} хэрэглэгчийн мэдээлэл шинэчлэгдлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{username} хэрэглэгчийн мэдээлэл шинэчлэгдлээ."))

    if path == "/kpi":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        page = kpi_list_page(conn, user, notice=qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/kpi/create" and method == "POST":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        form = parse_post(environ)
        name = normalize_text(form.get("name"))
        description = normalize_text(form.get("description"))
        if not name:
            page = kpi_list_page(conn, user, error="Лавлахын нэр оруулна уу.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        slug = f"kpi-{int(now_utc().timestamp())}"
        timestamp = now_utc().isoformat()
        conn.execute(
            "INSERT INTO kpi_directories(name, slug, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (name, slug, description or "", timestamp, timestamp),
        )
        record_audit(conn, user["id"], "create", "kpi_directory", details=f"{name} KPI лавлах үүслээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, f"/kpi/{quote(slug)}?notice=" + quote(f"{name} лавлах үүслээ."))

    if path.startswith("/kpi/") and not path.endswith("/rows/new") and not "/rows/" in path:
        slug = unquote(path.strip("/").split("/")[1])
        directory = conn.execute("SELECT * FROM kpi_directories WHERE slug = ?", (slug,)).fetchone()
        if not directory:
            conn.close()
            return not_found(start_response)
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if path.endswith("/delete") and method == "POST":
            conn.execute("DELETE FROM kpi_directories WHERE id = ?", (directory["id"],))
            record_audit(conn, user["id"], "delete", "kpi_directory", details=f"{directory['name']} KPI лавлах устгагдлаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/kpi?notice=" + quote(f"{directory['name']} лавлах устгагдлаа."))
        page = kpi_directory_page(conn, user, directory, notice=qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path.startswith("/kpi/") and path.endswith("/rows/new") and method == "POST":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        slug = unquote(path.strip("/").split("/")[1])
        directory = conn.execute("SELECT * FROM kpi_directories WHERE slug = ?", (slug,)).fetchone()
        if not directory:
            conn.close()
            return not_found(start_response)
        form = parse_post(environ)
        indicator = normalize_text(form.get("indicator"))
        if not indicator:
            page = kpi_directory_page(conn, user, directory, error="Шалгуур үзүүлэлт оруулна уу.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        freq = normalize_text(form.get("frequency"))
        if freq not in FREQUENCY_OPTIONS:
            freq = ""
        due_date = form.get("due_date", "").strip()
        try:
            dt.date.fromisoformat(due_date)
        except (ValueError, TypeError):
            due_date = ""
        max_order = conn.execute("SELECT MAX(order_num) FROM kpi_items WHERE directory_id = ?", (directory["id"],)).fetchone()[0] or 0
        timestamp = now_utc().isoformat()
        conn.execute(
            "INSERT INTO kpi_items(directory_id, order_num, indicator, description, formula, target_level, frequency, due_date, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (directory["id"], max_order + 1, indicator, normalize_text(form.get("description")) or "",
             normalize_text(form.get("formula")) or "", normalize_text(form.get("target_level")) or "",
             freq, due_date, timestamp, timestamp),
        )
        conn.commit()
        conn.close()
        return redirect(start_response, f"/kpi/{quote(slug)}?notice=" + quote("Мөр нэмэгдлээ."))

    if "/kpi/" in path and "/rows/" in path and path.endswith("/edit") and method == "POST":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        parts_kpi = path.strip("/").split("/")
        slug = unquote(parts_kpi[1])
        row_id = parts_kpi[3]
        directory = conn.execute("SELECT * FROM kpi_directories WHERE slug = ?", (slug,)).fetchone()
        if not directory:
            conn.close()
            return not_found(start_response)
        form = parse_post(environ)
        freq = normalize_text(form.get("frequency"))
        if freq not in FREQUENCY_OPTIONS:
            freq = ""
        due_date = form.get("due_date", "").strip()
        try:
            dt.date.fromisoformat(due_date)
        except (ValueError, TypeError):
            due_date = ""
        timestamp = now_utc().isoformat()
        conn.execute(
            "UPDATE kpi_items SET indicator=?, description=?, formula=?, target_level=?, frequency=?, due_date=?, updated_at=? WHERE id=? AND directory_id=?",
            (normalize_text(form.get("indicator")) or "", normalize_text(form.get("description")) or "",
             normalize_text(form.get("formula")) or "", normalize_text(form.get("target_level")) or "",
             freq, due_date, timestamp, row_id, directory["id"]),
        )
        conn.commit()
        conn.close()
        return redirect(start_response, f"/kpi/{quote(slug)}?notice=" + quote("KPI мөр шинэчлэгдлээ."))

    if "/kpi/" in path and "/rows/" in path and path.endswith("/delete") and method == "POST":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        parts_kpi = path.strip("/").split("/")
        slug = unquote(parts_kpi[1])
        row_id = parts_kpi[3]
        directory = conn.execute("SELECT * FROM kpi_directories WHERE slug = ?", (slug,)).fetchone()
        if not directory:
            conn.close()
            return not_found(start_response)
        conn.execute("DELETE FROM kpi_items WHERE id = ? AND directory_id = ?", (row_id, directory["id"]))
        conn.commit()
        conn.close()
        return redirect(start_response, f"/kpi/{quote(slug)}?notice=" + quote("KPI мөр устгагдлаа."))

    if path.startswith("/users/") and path.endswith("/delete") and method == "POST":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        target_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, target_id)
        if not target_user:
            conn.close()
            return not_found(start_response)
        if target_user["id"] == user["id"]:
            conn.close()
            page = users_page(conn, user, error="Өөрийгөө устгах боломжгүй.")
            return response(start_response, "400 Bad Request", page)
        conn.execute("DELETE FROM users WHERE id = ?", (target_user["id"],))
        record_audit(conn, user["id"], "delete", "user", entity_id=target_user["id"], target_user_id=target_user["id"], details=f"{target_user['username']} хэрэглэгч устгагдлаа.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{target_user['username']} хэрэглэгч устгагдлаа."))

    if path.startswith("/departments/"):
        parts = [unquote(part) for part in path.strip("/").split("/")]
        if len(parts) < 3 or parts[0] != "departments" or parts[2] != "assets":
            conn.close()
            return not_found(start_response)
        department = get_department(conn, parts[1])
        if not can_access_department(user, department, conn):
            conn.close()
            return forbidden(start_response)
        permissions = get_department_permissions(conn, department["id"])
        user_can_update = can_update_in_department(user, department, conn)

        if len(parts) == 3 and method == "GET":
            page = asset_list_page(conn, user, department, qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)

        if len(parts) == 4 and parts[3] == "new":
            if not user_can_update:
                conn.close()
                return forbidden(start_response)
            if method == "GET":
                page = render_page("Шинэ хөрөнгө", user, render_asset_form(path, user, department, {}, permissions))
                conn.close()
                return response(start_response, "200 OK", page)
            form = parse_post(environ)
            values, error = validate_asset_form(form, user, permissions)
            if error:
                page = render_page("Шинэ хөрөнгө", user, render_asset_form(path, user, department, form, permissions, error=error))
                conn.close()
                return response(start_response, "400 Bad Request", page)
            timestamp = now_utc().isoformat()
            conn.execute(
                """
                INSERT INTO assets (
                    department_id, asset_name, description, asset_type, asset_group_code,
                    has_personal_data, has_sensitive_data, owner, custodian, location,
                    access_right, retention_period, confidentiality, integrity_impact,
                    availability_impact, asset_value, asset_category, review_frequency, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    department["id"], values["asset_name"], values["description"], values["asset_type"], values["asset_group_code"],
                    values["has_personal_data"], values["has_sensitive_data"], values["owner"], values["custodian"], values["location"],
                    values["access_right"], values["retention_period"], values["confidentiality"], values["integrity_impact"], values["availability_impact"],
                    values["asset_value"], values["asset_category"], values.get("review_frequency", ""), timestamp, timestamp,
                ),
            )
            asset_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            record_audit(conn, user["id"], "create", "asset", entity_id=asset_id, department_id=department["id"], details=f"{values['asset_name']} хөрөнгө үүслээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/departments/{department['slug']}/assets?notice=" + quote("Хөрөнгө үүслээ."))

        if len(parts) == 4 and method == "GET":
            asset = get_asset(conn, parts[3], department["id"])
            if not asset:
                conn.close()
                return not_found(start_response)
            page = asset_detail_page(user, department, asset, qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)

        if len(parts) == 5 and parts[4] == "edit":
            if not user_can_update:
                conn.close()
                return forbidden(start_response)
            asset = get_asset(conn, parts[3], department["id"])
            if not asset:
                conn.close()
                return not_found(start_response)
            if method == "GET":
                page = render_page("Хөрөнгө засах", user, render_asset_form(path, user, department, asset, permissions, submit_label="Өөрчлөлт хадгалах"))
                conn.close()
                return response(start_response, "200 OK", page)
            form = parse_post(environ)
            values, error = validate_asset_form(form, user, permissions, existing_asset=asset)
            if error:
                merged = {key: form.get(key, asset[key]) for key, _, _ in ASSET_FIELDS}
                page = render_page("Хөрөнгө засах", user, render_asset_form(path, user, department, merged, permissions, error=error, submit_label="Өөрчлөлт хадгалах"))
                conn.close()
                return response(start_response, "400 Bad Request", page)
            values["updated_at"] = now_utc().isoformat()
            values["id"] = asset["id"]
            conn.execute(
                """
                UPDATE assets
                SET asset_name = :asset_name,
                    description = :description,
                    asset_type = :asset_type,
                    asset_group_code = :asset_group_code,
                    has_personal_data = :has_personal_data,
                    has_sensitive_data = :has_sensitive_data,
                    owner = :owner,
                    custodian = :custodian,
                    location = :location,
                    access_right = :access_right,
                    retention_period = :retention_period,
                    confidentiality = :confidentiality,
                    integrity_impact = :integrity_impact,
                    availability_impact = :availability_impact,
                    asset_value = :asset_value,
                    asset_category = :asset_category,
                    review_frequency = :review_frequency,
                    updated_at = :updated_at
                WHERE id = :id
                """,
                values,
            )
            record_audit(conn, user["id"], "update", "asset", entity_id=asset["id"], department_id=department["id"], details=f"{values['asset_name']} хөрөнгө шинэчлэгдлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/departments/{department['slug']}/assets?notice=" + quote("Хөрөнгө шинэчлэгдлээ."))

        if len(parts) == 5 and parts[4] == "delete" and method == "POST":
            if not user_can_update:
                conn.close()
                return forbidden(start_response)
            asset = get_asset(conn, parts[3], department["id"])
            if not asset:
                conn.close()
                return not_found(start_response)
            conn.execute("DELETE FROM assets WHERE id = ? AND department_id = ?", (parts[3], department["id"]))
            record_audit(conn, user["id"], "delete", "asset", entity_id=parts[3], department_id=department["id"], details=f"{asset['asset_name']} хөрөнгө устгагдлаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/departments/{department['slug']}/assets?notice=" + quote("Хөрөнгө устгагдлаа."))

    conn.close()
    return not_found(start_response)


def gen_cert():
    """Generate a self-signed TLS certificate for internal use."""
    ssl_dir = DATA_DIR / "ssl"
    ssl_dir.mkdir(parents=True, exist_ok=True)
    cert_path = ssl_dir / "cert.pem"
    key_path = ssl_dir / "key.pem"
    if cert_path.exists() and key_path.exists():
        print(f"Certificates already exist in {ssl_dir}/")
        print("Delete them first if you want to regenerate.")
        return
    hostname = os.environ.get("BURTGEL_HOSTNAME", "burtgel.internal")
    subj = f"/C=MN/ST=Ulaanbaatar/L=Ulaanbaatar/O=DICO/OU=IT/CN={hostname}"
    san = f"subjectAltName=DNS:{hostname},DNS:localhost,IP:127.0.0.1"
    try:
        subprocess.run(
            [
                "openssl", "req",
                "-x509",
                "-newkey", "rsa:4096",
                "-keyout", str(key_path),
                "-out", str(cert_path),
                "-days", "3650",
                "-nodes",
                "-subj", subj,
                "-addext", san,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        sys.exit("ERROR: 'openssl' command not found. Install it with: dnf install openssl")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"ERROR: openssl failed:\n{exc.stderr.decode()}")
    os.chmod(key_path, 0o600)
    print("Self-signed certificate generated successfully.")
    print(f"  Certificate : {cert_path}")
    print(f"  Private key : {key_path}")
    print(f"  Valid for   : 10 years  |  CN={hostname}")
    print()
    print("To avoid browser warnings on client machines, import the certificate")
    print(f"into the OS/browser trust store: {cert_path}")
    print()
    print("On Windows: certmgr.msc → Trusted Root Certification Authorities → Import")
    print("On Linux  : cp cert.pem /usr/local/share/ca-certificates/burtgel.crt && update-ca-certificates")
    print("On macOS  : Keychain Access → System → import, then set 'Always Trust'")


def main():
    # ------------------------------------------------------------------ #
    # Subcommands that do not require the server secret key               #
    # ------------------------------------------------------------------ #
    if len(sys.argv) > 1 and sys.argv[1] == "gen-cert":
        gen_cert()
        return

    # ------------------------------------------------------------------ #
    # Enforce strong secret key before starting the server                #
    # ------------------------------------------------------------------ #
    if SECRET_KEY == "change-me-before-production" or not SECRET_KEY:
        sys.exit(
            "ERROR: BURTGEL_SECRET_KEY environment variable is not set or still uses the default value.\n"
            "Generate a strong key and export it before starting:\n\n"
            "  export BURTGEL_SECRET_KEY=\"$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')\"\n"
        )

    ensure_database()

    if len(sys.argv) > 1 and sys.argv[1] == "sync-csv":
        conn = get_db()
        try:
            sync_assets_from_csv(conn, Path(sys.argv[2]) if len(sys.argv) > 2 else CSV_IMPORT_FILE)
            seed_permissions(conn)
        finally:
            conn.close()
        print("CSV sync completed.")
        return

    # ------------------------------------------------------------------ #
    # Start HTTPS or HTTP server                                          #
    # ------------------------------------------------------------------ #
    use_ssl = SSL_CERT.exists() and SSL_KEY.exists()
    scheme = "https" if use_ssl else "http"

    if not use_ssl:
        print(
            "WARNING: SSL certificates not found. Running in plain HTTP mode.\n"
            f"  Run 'python3 app.py gen-cert' then restart to enable HTTPS.\n"
            f"  Expected cert: {SSL_CERT}\n"
            f"  Expected key : {SSL_KEY}"
        )

    print(f"Burtgel is listening on {scheme}://{HOST}:{PORT}")

    with make_server(HOST, PORT, app) as server:
        if use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=SSL_CERT, keyfile=SSL_KEY)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
