#!/usr/bin/env python3
import csv
import datetime as dt
import hashlib
import mimetypes
import hmac
import html
import os
import secrets
import sqlite3
import sys
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote
from wsgiref.simple_server import make_server
from xml.etree import ElementTree as ET
from zipfile import ZipFile


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DOCS_DIR = DATA_DIR
DB_PATH = Path(os.environ.get("BURTGEL_DB_PATH", DATA_DIR / "burtgel.db"))
IMPORT_DIR = Path(os.environ.get("BURTGEL_IMPORT_DIR", BASE_DIR / "extracted"))
HOST = os.environ.get("BURTGEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("BURTGEL_PORT", "8000"))
SESSION_COOKIE = "burtgel_session"
SECRET_KEY = os.environ.get("BURTGEL_SECRET_KEY", "change-me-before-production")

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
DEFAULT_USERS = [
    ("admin", "admin123", None, 1),
    ("fra_user", "fra123", "fra", 0),
    ("legal_user", "legal123", "legal", 0),
    ("md_user", "md123", "md", 0),
    ("stg_user", "stg123", "stg", 0),
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
    try:
        salt, expected = stored_value.split("$", 1)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return hmac.compare_digest(actual, expected)


def now_utc():
    return dt.datetime.utcnow().replace(microsecond=0)


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


def parse_post(environ):
    try:
        size = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        size = 0
    raw = environ["wsgi.input"].read(size).decode("utf-8")
    return {key: values[0] if values else "" for key, values in parse_qs(raw, keep_blank_values=True).items()}


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
        return dt.datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
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
            password_hash TEXT NOT NULL,
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login_at TEXT
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
        """
    )
    ensure_column(conn, "users", "last_login_at", "TEXT")
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
    for username, password, dept_slug, is_admin in DEFAULT_USERS:
        if username in existing:
            continue
        department_id = department_lookup.get(dept_slug) if dept_slug else None
        conn.execute(
            """
            INSERT INTO users(username, password_hash, department_id, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, hash_password(password), department_id, is_admin, now_utc().isoformat()),
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
    username, password = spec["user"]
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE users SET department_id = ?, is_admin = 0, is_active = 1 WHERE id = ?",
            (department_id, existing["id"]),
        )
        return
    conn.execute(
        """
        INSERT INTO users(username, password_hash, department_id, is_admin, created_at)
        VALUES (?, ?, ?, 0, ?)
        """,
        (username, hash_password(password), department_id, now_utc().isoformat()),
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


def ensure_database():
    conn = get_db()
    create_schema(conn)
    import_assets(conn)
    seed_users(conn)
    seed_permissions(conn)
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
    if dt.datetime.fromisoformat(session_row["expires_at"]) < now_utc():
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


def departments_for_user(conn, user):
    if user["is_admin"]:
        return list(conn.execute("SELECT * FROM departments ORDER BY name"))
    return list(conn.execute("SELECT * FROM departments WHERE id = ? ORDER BY name", (user["department_id"],)))


def can_access_department(user, department):
    return bool(user and department and (user["is_admin"] or user["department_id"] == department["id"]))


def get_department_permissions(conn, department_id):
    rows = conn.execute(
        "SELECT field_name, can_edit FROM department_column_permissions WHERE department_id = ?",
        (department_id,),
    ).fetchall()
    permissions = {row["field_name"]: bool(row["can_edit"]) for row in rows}
    for field_name, _, _ in ASSET_FIELDS:
        permissions.setdefault(field_name, True)
    return permissions


def can_edit_field(user, permissions, field_name):
    return bool(user and (user["is_admin"] or permissions.get(field_name, True)))


def get_attachment_register(slug):
    for register in ATTACHMENT_REGISTERS:
        if register["slug"] == slug:
            return register
    return None


def nav_links(user):
    if not user:
        return ""
    links = ['<a href="/dashboard">Хяналтын самбар</a>']
    if user["is_admin"]:
        links.append('<a href="/users">Хэрэглэгчид</a>')
        links.append('<a href="/permissions">Баганын эрх</a>')
        links.append('<a href="/audit">Аудит лог</a>')
        links.append('<a href="/admin-docs">Админ баримтууд</a>')
    links.append('<a href="/account/password">Нууц үг солих</a>')
    links.append('<form method="post" action="/logout" class="inline-form"><button type="submit">Гарах</button></form>')
    return "".join(f"<li>{item}</li>" for item in links)


def render_page(title, user, content, notice=""):
    auth_summary = ""
    if user:
        dept_label = "Бүх хэлтэс" if user["is_admin"] else html.escape(user["department_name"] or "-")
        auth_summary = (
            f'<div class="user-chip"><strong>{html.escape(user["username"])}</strong>'
            f'<span>{dept_label}</span></div>'
        )
    return f"""<!doctype html>
<html lang=\"mn\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{html.escape(title)} | Burtgel</title>
  <link rel=\"stylesheet\" href=\"/static/styles.css\">
</head>
<body>
  <div class=\"shell\">
    <header class=\"topbar\">
      <div>
        <a href=\"/dashboard\" class=\"brand\">burtgel</a>
        <p class=\"subtitle\">Хэлтсийн хөрөнгийн бүртгэл</p>
      </div>
      {auth_summary}
    </header>
    <div class=\"content-grid\">
      <aside class=\"sidebar\">
        <ul class=\"nav\">{nav_links(user)}</ul>
      </aside>
      <main class=\"main\">
        {fmt_notice(notice)}
        {content}
      </main>
    </div>
  </div>
</body>
</html>"""


def not_found(start_response):
    return response(start_response, "404 Not Found", render_page("Олдсонгүй", None, "<h1>Хуудас олдсонгүй</h1>"))


def forbidden(start_response):
    return response(start_response, "403 Forbidden", render_page("Хандах эрхгүй", None, "<h1>Хандах эрхгүй</h1>"))


def login_form(error="", notice=""):
    body = f"""
    <section class=\"panel panel-narrow\">
      <h1>Нэвтрэх</h1>
      <p class=\"muted\">Админ эрхгүй хэрэглэгч зөвхөн өөрийн хэлтсийн мэдээлэлд хандана.</p>
      {fmt_error(error)}
      {fmt_notice(notice)}
      <form method=\"post\" action=\"/login\" class=\"stack-form\">
        <label>Хэрэглэгчийн нэр<input type=\"text\" name=\"username\" required autofocus></label>
        <label>Нууц үг<input type=\"password\" name=\"password\" required></label>
        <button type=\"submit\">Нэвтрэх</button>
      </form>
      <div class=\"helper\">
    </section>
    """
    return render_page("Нэвтрэх", None, body)


def dashboard_page(conn, user, notice=""):
    cards = []
    for department in departments_for_user(conn, user):
        count = conn.execute("SELECT COUNT(*) FROM assets WHERE department_id = ?", (department["id"],)).fetchone()[0]
        cards.append(
            f"""
            <article class=\"card\">
              <h2>{html.escape(department['name'])}</h2>
              <p>{count} хөрөнгө</p>
              <a class=\"button-link\" href=\"/departments/{html.escape(department['slug'])}/assets\">Бүртгэл нээх</a>
            </article>
            """
        )
    body = f"""
    <section class=\"panel\">
      <h1>Хэлтсүүд</h1>
      <p class=\"muted\">Эрхийн бүтэц нь энгийн: нэг хэрэглэгч нэг хэлтэст харьяална, харин админ бүх мэдээллийг харна.</p>
      <div class=\"card-grid\">{''.join(cards) if cards else '<p>Энэ хэрэглэгчид хэлтэс оноогоогүй байна.</p>'}</div>
    </section>
    """
    return render_page("Хяналтын самбар", user, body, notice)


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
        <div class=\"actions\"><button type=\"submit\">{submit_label}</button></div>
      </form>
    </section>
    """
    return body


def asset_list_page(conn, user, department, notice=""):
    rows = conn.execute(
        """
        SELECT id, asset_name, asset_type, asset_group_code, owner, asset_category, updated_at
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
            <tr>{''.join(f'<th>{label}</th>' for _, label in LIST_FIELDS)}<th></th></tr>
          </thead>
          <tbody>
            {''.join(body_rows) if body_rows else '<tr><td colspan="7">Энэ хэлтэст одоогоор хөрөнгө бүртгэгдээгүй байна.</td></tr>'}
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
            <article class=\"detail-item\">
              <div class=\"detail-label\">{html.escape(label)}</div>
              <div class=\"detail-value\">{format_multiline(asset[field_name])}</div>
            </article>
            """
        )
    items.append(
        f"""
        <article class=\"detail-item\">
          <div class=\"detail-label\">Сүүлд өөрчилсөн</div>
          <div class=\"detail-value\">{format_dt(asset['updated_at'])}</div>
        </article>
        """
    )
    body = f"""
    <section class=\"panel\">
      <div class=\"heading-row\">
        <div>
          <h1>{html.escape(asset['asset_name'])}</h1>
          <p class=\"muted\">Excel файлаас орж ирсэн бүх талбар энд харагдана.</p>
        </div>
        <div class=\"action-strip\">
          <a class=\"button-link ghost\" href=\"/departments/{html.escape(department['slug'])}/assets\">Буцах</a>
          <a class=\"button-link ghost\" href=\"/departments/{html.escape(department['slug'])}/assets/{asset['id']}/edit\">Засах</a>
        </div>
      </div>
      <div class=\"detail-grid\">{''.join(items)}</div>
    </section>
    """
    return render_page(asset['asset_name'], user, body, notice)


def password_change_page(user, error="", notice=""):
    body = f"""
    <section class=\"panel panel-narrow\">
      <h1>Нууц үг солих</h1>
      <p class=\"muted\">Одоогийн нууц үгээ баталгаажуулаад шинэ нууц үгээ оруулна уу.</p>
      {fmt_error(error)}
      {fmt_notice(notice)}
      <form method=\"post\" action=\"/account/password\" class=\"stack-form\">
        <label>Одоогийн нууц үг<input type=\"password\" name=\"current_password\" required></label>
        <label>Шинэ нууц үг<input type=\"password\" name=\"new_password\" required></label>
        <label>Шинэ нууц үг давтах<input type=\"password\" name=\"confirm_password\" required></label>
        <button type=\"submit\">Шинэчлэх</button>
      </form>
    </section>
    """
    return render_page("Нууц үг солих", user, body, notice)


def reset_password_page(user, target_user, error="", notice=""):
    dept_label = target_user["department_name"] or "Бүх хэлтэс"
    body = f"""
    <section class=\"panel panel-narrow\">
      <h1>Нууц үг шинэчлэх</h1>
      <p class=\"muted\"><strong>{html.escape(target_user['username'])}</strong> хэрэглэгчийн нууц үгийг админ шинээр тохируулна. Хэлтэс: {html.escape(dept_label)}</p>
      {fmt_error(error)}
      {fmt_notice(notice)}
      <form method=\"post\" action=\"/users/{target_user['id']}/reset-password\" class=\"stack-form\">
        <label>Шинэ нууц үг<input type=\"password\" name=\"new_password\" required></label>
        <label>Шинэ нууц үг давтах<input type=\"password\" name=\"confirm_password\" required></label>
        <button type=\"submit\">Нууц үг шинэчлэх</button>
      </form>
      <a class=\"button-link ghost\" href=\"/users\">Хэрэглэгчид рүү буцах</a>
    </section>
    """
    return render_page("Нууц үг шинэчлэх", user, body, notice)


def users_page(conn, user, notice="", error=""):
    departments = list(conn.execute("SELECT * FROM departments ORDER BY name"))
    user_rows = conn.execute(
        """
        SELECT users.id, users.username, users.is_admin, users.is_active, users.last_login_at,
               departments.name AS department_name
        FROM users
        LEFT JOIN departments ON departments.id = users.department_id
        ORDER BY users.is_admin DESC, users.username
        """
    ).fetchall()
    options = ['<option value="">Хэлтэсгүй</option>']
    for department in departments:
        options.append(f'<option value="{department["id"]}">{html.escape(department["name"])}</option>')
    rows = []
    for row in user_rows:
        dept = row["department_name"] or "Бүх хэлтэс"
        role = "Админ" if row["is_admin"] else "Хэлтэс"
        rows.append(
            f"""
            <tr>
              <td>{html.escape(row['username'])}</td>
              <td>{html.escape(dept)}</td>
              <td>{role}</td>
              <td>{format_dt(row['last_login_at'])}</td>
              <td>{'Идэвхтэй' if row['is_active'] else 'Идэвхгүй'}</td>
              <td class=\"table-actions\">
                <div class=\"action-strip\">
                  <a class=\"button-link ghost small\" href=\"/users/{row['id']}/reset-password\">Нууц үг шинэчлэх</a>
                  <form method=\"post\" action=\"/users/{row['id']}/delete\" class=\"inline-form\" onsubmit="return confirm(\'Устгахдаа итгэлтэй байна уу?\')">
                    <button type=\"submit\" class=\"link-button danger\">Устгах</button>
                  </form>
                </div>
              </td>
            </tr>
            """
        )
    body = f"""
    <section class=\"panel\">
      <h1>Хэрэглэгчийн эрх</h1>
      <p class=\"muted\">Админ хэрэглэгч бүх хэлтсийг харна. Сүүлийн нэвтрэлтийн огноо мөн харагдана.</p>
      {fmt_error(error)}
      <form method=\"post\" action=\"/users\" class=\"user-form\">
        <label>Хэрэглэгчийн нэр<input type=\"text\" name=\"username\" required></label>
        <label>Нууц үг<input type=\"password\" name=\"password\" required></label>
        <label>Хэлтэс<select name=\"department_id\">{''.join(options)}</select></label>
        <label class=\"checkbox\"><input type=\"checkbox\" name=\"is_admin\" value=\"1\"> Админ эрхтэй хэрэглэгч</label>
        <button type=\"submit\">Хэрэглэгч үүсгэх</button>
      </form>
    </section>
    <section class=\"panel\">
      <div class=\"table-wrap\">
        <table>
          <thead>
            <tr>
              <th>Хэрэглэгчийн нэр</th>
              <th>Хэлтэс</th>
              <th>Эрх</th>
              <th>Сүүлд нэвтэрсэн</th>
              <th>Төлөв</th>
              <th></th>
            </tr>
          </thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """
    return render_page("Хэрэглэгчид", user, body, notice)


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
            <section class=\"panel\">
              <h2>{html.escape(department['name'])}</h2>
              <p class=\"muted\">Энэ хэлтсийн энгийн хэрэглэгч ямар талбарыг засаж болохыг тохируулна.</p>
              <div class=\"permissions-grid\">{''.join(items)}</div>
            </section>
            """
        )
    body = f"""
    <form method=\"post\" action=\"/permissions\" class=\"stack-form\">
      {''.join(panels)}
      <section class=\"panel\"><button type=\"submit\">Эрх шинэчлэх</button></section>
    </form>
    """
    return render_page("Баганын эрх", user, body, notice)


def list_admin_documents():
    docs = []
    for item in sorted(DOCS_DIR.iterdir(), key=lambda p: p.name.lower()):
        if not item.is_file() or item.name == DB_PATH.name or item.name.startswith("Хавсралт"):
            continue
        docs.append(item)
    return docs


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


def admin_documents_page(user, notice=""):
    register_cards = []
    for register in ATTACHMENT_REGISTERS:
        register_cards.append(
            f"""
            <article class="card">
              <h2>{html.escape(register['title'])}</h2>
              <p class="muted">{html.escape(register['description'])}</p>
              <div class="action-strip">
                <a class="button-link" href="/admin-docs/registers/{html.escape(register['slug'])}">Бүртгэл нээх</a>
              </div>
            </article>
            """
        )
    docs = list_admin_documents()
    items = []
    for doc in docs:
        view_href = f"/admin-docs/{quote(doc.name)}"
        download_href = f"/admin-docs/{quote(doc.name)}/download"
        items.append(
            f"""
            <article class="card">
              <h2>{html.escape(doc.name)}</h2>
              <p class="muted">Төрөл: {html.escape(doc.suffix.lstrip('.') or "file").upper()}</p>
              <div class="action-strip">
                <a class="button-link" href="{view_href}">Нээж үзэх</a>
                <a class="button-link ghost" href="{download_href}">Татах</a>
              </div>
            </article>
            """
        )
    body = f"""
    <section class="panel">
      <h1>Админ баримтууд</h1>
      <p class="muted">Хавсралт маягтуудыг систем дээр мөрөөр нь бүртгэнэ. Бусад баримтыг хүсвэл нээж үзэх эсвэл татаж авна.</p>
      <div class="card-grid">{''.join(register_cards)}</div>
    </section>
    <section class="panel">
      <h2>Бусад файл</h2>
      <div class="card-grid">{''.join(items) if items else '<p>Файл алга.</p>'}</div>
    </section>
    """
    return render_page("Админ баримтууд", user, body, notice)


def admin_document_view_page(user, file_path, notice=""):
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
          <a class="button-link ghost" href="/admin-docs">Буцах</a>
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
        body_rows.append(
            f"""
            <tr>
              <td class="audit-col-time">{format_dt(row['created_at'])}</td>
              <td class="audit-col-actor">{html.escape(row['actor_username'] or 'Систем')}</td>
              <td class="audit-col-action"><span class="audit-pill">{html.escape(row['action'])}</span></td>
              <td class="audit-col-type"><span class="audit-pill ghost">{html.escape(row['entity_type'])}</span></td>
              <td class="audit-col-id">{html.escape(row['entity_id'] or '-')}</td>
              <td class="audit-col-department">{html.escape(row['department_name'] or '-')}</td>
              <td class="audit-col-target">{html.escape(row['target_username'] or '-')}</td>
              <td class="audit-col-details">{format_multiline(row['details'] or '-')}</td>
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
              <th class="audit-col-type">Төрөл</th>
              <th class="audit-col-id">ID</th>
              <th class="audit-col-department">Хэлтэс</th>
              <th class="audit-col-target">Зорилтот хэрэглэгч</th>
              <th class="audit-col-details">Дэлгэрэнгүй</th>
            </tr>
          </thead>
          <tbody>{''.join(body_rows) if body_rows else '<tr><td colspan="8">Одоогоор аудит лог алга.</td></tr>'}</tbody>
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

    if path == "/":
        conn.close()
        return redirect(start_response, "/dashboard" if user else "/login")

    if path == "/login":
        if method == "GET":
            page = login_form(notice=qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        candidate = conn.execute(
            """
            SELECT users.*, departments.slug AS department_slug, departments.name AS department_name
            FROM users
            LEFT JOIN departments ON departments.id = users.department_id
            WHERE username = ? AND is_active = 1
            """,
            (normalize_text(form.get("username")),),
        ).fetchone()
        if not candidate or not verify_password(form.get("password", ""), candidate["password_hash"]):
            attempted_username = normalize_text(form.get("username")) or "(хоосон)"
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
            page = login_form(error="Хэрэглэгчийн нэр эсвэл нууц үг буруу байна.")
            conn.close()
            return response(start_response, "401 Unauthorized", page)
        session_id = create_session(conn, candidate["id"])
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_utc().isoformat(), candidate["id"]))
        record_audit(conn, candidate["id"], "login", "session", entity_id=session_id, department_id=candidate["department_id"], details="Хэрэглэгч системд нэвтэрлээ.")
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

    if path == "/dashboard":
        page = dashboard_page(conn, user, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

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
        if len(form.get("new_password", "")) < 6:
            page = password_change_page(user, error="Шинэ нууц үг хамгийн багадаа 6 тэмдэгт байна.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        if form.get("new_password", "") != form.get("confirm_password", ""):
            page = password_change_page(user, error="Шинэ нууц үг таарахгүй байна.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(form.get("new_password", "")), user["id"]))
        record_audit(conn, user["id"], "change_password", "user", entity_id=user["id"], department_id=user["department_id"], target_user_id=user["id"], details="Хэрэглэгч өөрийн нууц үгийг сольсон.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/account/password?notice=" + quote("Нууц үг амжилттай солигдлоо."))

    if path == "/users":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        if method == "GET":
            page = users_page(conn, user, notice=qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        username = normalize_text(form.get("username"))
        password = form.get("password", "")
        department_id = form.get("department_id") or None
        is_admin = 1 if form.get("is_admin") == "1" else 0
        if not username or not password:
            page = users_page(conn, user, error="Хэрэглэгчийн нэр болон нууц үгээ оруулна уу.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        try:
            conn.execute(
                """
                INSERT INTO users(username, password_hash, department_id, is_admin, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, hash_password(password), department_id, is_admin, now_utc().isoformat()),
            )
            target_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
            record_audit(conn, user["id"], "create", "user", entity_id=target_id, department_id=department_id, target_user_id=target_id, details=f"{username} хэрэглэгч үүслээ.")
            conn.commit()
        except sqlite3.IntegrityError:
            page = users_page(conn, user, error="Энэ хэрэглэгчийн нэр бүртгэлтэй байна.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{username} хэрэглэгч үүслээ."))

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
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        page = admin_documents_page(user, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

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

    if path.startswith("/admin-docs/"):
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        suffix = path.split("/admin-docs/", 1)[1]
        is_download = suffix.endswith("/download")
        raw_name = suffix[:-9] if is_download else suffix
        file_path = resolve_admin_document(raw_name)
        if not file_path:
            conn.close()
            return not_found(start_response)
        try:
            file_path.relative_to(DOCS_DIR.resolve())
        except ValueError:
            conn.close()
            return forbidden(start_response)
        if is_download:
            record_audit(conn, user["id"], "download", "admin_document", entity_id=file_path.name, details=f"{file_path.name} баримтыг татлаа.")
            conn.commit()
            conn.close()
            return send_file(start_response, file_path)
        page = admin_document_view_page(user, file_path, qs_value(query, "notice"))
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
        form = parse_post(environ)
        if len(form.get("new_password", "")) < 6:
            page = reset_password_page(user, target_user, error="Шинэ нууц үг хамгийн багадаа 6 тэмдэгт байна.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        if form.get("new_password", "") != form.get("confirm_password", ""):
            page = reset_password_page(user, target_user, error="Шинэ нууц үг таарахгүй байна.")
            conn.close()
            return response(start_response, "400 Bad Request", page)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(form.get("new_password", "")), user_id))
        record_audit(conn, user["id"], "reset_password", "user", entity_id=user_id, department_id=target_user["department_id"], target_user_id=user_id, details=f"{target_user['username']} хэрэглэгчийн нууц үгийг админ шинэчиллээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{target_user['username']} хэрэглэгчийн нууц үг шинэчлэгдлээ."))

    if path.startswith("/users/") and path.endswith("/delete") and method == "POST":
        if not user["is_admin"]:
            conn.close()
            return forbidden(start_response)
        user_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, user_id)
        if not target_user:
            conn.close()
            return not_found(start_response)
        if str(user["id"]) == user_id:
            conn.close()
            return redirect(start_response, "/users?notice=" + quote("Өөрийн бүртгэлийг устгах боломжгүй."))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        record_audit(conn, user["id"], "delete", "user", entity_id=user_id, department_id=target_user["department_id"], target_user_id=user_id, details=f"{target_user['username']} хэрэглэгч устгагдлаа.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/users?notice=" + quote("Хэрэглэгч устгагдлаа."))

    if path.startswith("/departments/"):
        parts = [unquote(part) for part in path.strip("/").split("/")]
        if len(parts) < 3 or parts[0] != "departments" or parts[2] != "assets":
            conn.close()
            return not_found(start_response)
        department = get_department(conn, parts[1])
        if not can_access_department(user, department):
            conn.close()
            return forbidden(start_response)
        permissions = get_department_permissions(conn, department["id"])

        if len(parts) == 3 and method == "GET":
            page = asset_list_page(conn, user, department, qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)

        if len(parts) == 4 and parts[3] == "new":
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
                    availability_impact, asset_value, asset_category, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    department["id"], values["asset_name"], values["description"], values["asset_type"], values["asset_group_code"],
                    values["has_personal_data"], values["has_sensitive_data"], values["owner"], values["custodian"], values["location"],
                    values["access_right"], values["retention_period"], values["confidentiality"], values["integrity_impact"], values["availability_impact"],
                    values["asset_value"], values["asset_category"], timestamp, timestamp,
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


def main():
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

    print(f"Burtgel is listening on http://{HOST}:{PORT}")
    with make_server(HOST, PORT, app) as server:
        server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
