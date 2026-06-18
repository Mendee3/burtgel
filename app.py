#!/usr/bin/env python3
import cgi
import csv
import datetime as dt
import email.mime.multipart
import email.mime.text
import hashlib
import json
import mimetypes
import hmac
import html
import io
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import uuid
import zlib
from zoneinfo import ZoneInfo
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode
import urllib.request as _urllib_request
from wsgiref.simple_server import make_server
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile

import openpyxl


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
DOCS_DIR = DATA_DIR
SUBFILES_DIR = DATA_DIR / "subfiles"
# Category slugs visible to all logged-in users (read-only)
PUBLIC_DOC_CATEGORY_SLUGS = {"батлагдсан-бичиг-баримт", "баримт-бичгийн-загвар"}
DB_PATH = Path(os.environ.get("BURTGEL_DB_PATH", DATA_DIR / "burtgel.db"))
IMPORT_DIR = Path(os.environ.get("BURTGEL_IMPORT_DIR", BASE_DIR / "extracted"))
HOST = os.environ.get("BURTGEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("BURTGEL_PORT", "8443"))
SSL_CERT = Path(os.environ.get("BURTGEL_CERT_FILE", DATA_DIR / "ssl" / "cert.pem"))
SSL_KEY = Path(os.environ.get("BURTGEL_KEY_FILE", DATA_DIR / "ssl" / "key.pem"))
SESSION_COOKIE = "burtgel_session"
SECRET_KEY = os.environ.get("BURTGEL_SECRET_KEY", "change-me-before-production")
PORTAL_SSO_SECRET = os.environ.get("PORTAL_SSO_SECRET", "change-me-before-production")
PORTAL_URL = os.environ.get("PORTAL_URL", "https://portal/")
PORTAL_ERROR_REDIRECT = PORTAL_URL.rstrip("/") + "?error=sso_error"
AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")
AZURE_REDIRECT_URI = os.environ.get("AZURE_REDIRECT_URI", "")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
APP_URL = os.environ.get("APP_URL", "http://burtgel/")
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
    ("asset_group_code", "Код", True),
    ("has_personal_data", "Хувь хүний мэдээлэл байгаа эсэх", True),
    ("has_sensitive_data", "Эмзэг мэдээлэл байгаа эсэх", True),
    ("owner", "Хөрөнгө эзэмшигч", True),
    ("custodian", "Хөрөнгийн хариуцагч", True),
    ("location", "Байршил", True),
    ("retention_period", "Хадгалах хугацаа", True),
    ("confidentiality", "Нууцлал", True),
    ("integrity_impact", "Бүрэн бүтэн байдал алдагдвал үүсэх нөлөөлөл", True),
    ("availability_impact", "Хүртээмжтэй байдал алдагдвал үүсэх нөлөөлөл", True),
    ("asset_value", "Хөрөнгийн үнэ цэн", False),
    ("asset_category", "Хөрөнгийн категори", False),
]
LIST_FIELDS = [
    ("asset_name", "Хөрөнгө"),
    ("asset_type", "Төрөл"),
    ("asset_group_code", "Код"),
    ("owner", "Эзэмшигч"),
    ("asset_category", "Категори"),
    ("updated_at", "Сүүлд өөрчилсөн"),
]
DROPDOWN_OPTIONS = {
    "asset_type": ["Цахим", "Биет"],
    "asset_group_code": [
        "IDA_CD", "IDA_PII", "IDA_PHI", "IDA_FD", "IDA_SL", "IDA_CF", "IDA_IP",
        "IDA_BD", "IDA_BDoc", "SA_EA", "SA_WA", "SA_OS", "SA_API", "SA_ST",
        "SA_DT", "SA_CVA", "HA_S", "HA_ND", "HA_UD", "HA_SD", "HA_ID",
        "NC_IN", "NC_EC", "NC_VI", "NC_CS", "NC_DS", "NC_NCR",
        "PA_PU", "PA_GU", "PA_D", "PA_E", "PA_CV", "PA_ST",
        "PD_PP", "PD_P", "PD_TM", "PD_ALR", "PD_OC",
    ],
    "has_personal_data": [("Тийм", "Y"), ("Үгүй", "N")],
    "has_sensitive_data": [("Тийм", "Y"), ("Үгүй", "N")],
    "confidentiality": ["Маш нууц-3", "Нууц-2", "Дотоод хэрэгцээнд-1"],
    "integrity_impact": ["Өндөр - 3", "Дунд - 2", "Бага - 1"],
    "availability_impact": ["Өндөр - 3", "Дунд - 2", "Бага - 1"],
}
ASSET_SCORE_MAP = {
    "Маш нууц-3": 3, "Нууц-2": 2, "Дотоод хэрэгцээнд-1": 1,
    "Өндөр - 3": 3, "Дунд - 2": 2, "Бага - 1": 1,
}
ASSET_SCORE_FIELDS = {"confidentiality", "integrity_impact", "availability_impact"}
ASSET_COMPUTED_FIELDS = {"asset_value", "asset_category"}
KOD_TABLE_DATA = [
    ("Мэдээлэл / өгөгдлийн хөрөнгө", [
        ("Харилцагчийн мэдээлэл",          "IDA_CD",   "Нэр, утасны дугаар, имэйл хаяг, хаяг, төлбөрийн мэдээлэл"),
        ("Хувь хүнийг таних мэдээлэл (PII)", "IDA_PII", "Регистрийн дугаар, иргэний үнэмлэх/паспортын мэдээлэл, төрсөн огноо, биометрик мэдээлэл"),
        ("Эрүүл мэндийн мэдээлэл (PHI)",   "IDA_PHI",  "Онош (жишээ нь: чихрийн шижин, даралт ихсэлт), эмчилгээний төлөвлөгөө эсвэл дэлгэрэнгүй мэдээлэл, шинжилгээний хариу (жишээ нь: рентген зураг, лабораторийн хариу), эмийн жор, эрүүл мэндийн үйлчилгээтэй холбоотой төлбөрийн мэдээлэл, эмч/сувилагчийн тэмдэглэл"),
        ("Санхүүгийн мэдээлэл",            "IDA_FD",   "Нэхэмжлэх, цалингийн бүртгэл, орлогын тайлан"),
        ("Системийн лог",                   "IDA_SL",   "Нэвтрэлтийн лог, галт ханын лог, SIEM лог"),
        ("Тохиргооны файлууд",              "IDA_CF",   "Систем, аппликейшн, галт ханын тохиргоо"),
        ("Оюуны өмч",                       "IDA_IP",   "Эх код, алгоритм, загвар дизайн"),
        ("Нөөцлөлтийн мэдээлэл",           "IDA_BD",   "Оффлайн болон cloud нөөцлөлт, snapshot"),
        ("Бизнесийн баримт бичиг",          "IDA_BDoc", "Бизнесийн гэрээнүүд (түншлэлийн гэрээ, борлуулалтын гэрээ, SLA), стратеги төлөвлөгөө, тактикийн төлөвлөгөө, бизнес төлөвлөгөө"),
    ]),
    ("Програм хангамжийн хөрөнгө", [
        ("Байгууллагын хэрэглээний системүүд", "SA_EA",  "CRM (Salesforce), ERP (SAP), төлбөр тооцооны системүүд"),
        ("Вэб болон мобайл аппликейшн",        "SA_WA",  "Харилцагчийн портал, өөртөө үйлчлэх аппликейшн"),
        ("Үйлдлийн системүүд",                 "SA_OS",  "Windows Server, Linux, iOS, Android"),
        ("Middleware болон API хэрэгслүүд",    "SA_API", "NGINX, Apache, API Gateway, Kafka"),
        ("Аюулгүй байдлын хэрэгслүүд",        "SA_ST",  "SIEM (Splunk), EDR (CrowdStrike), антивирус, DLP"),
        ("Хөгжүүлэлтийн хэрэгслүүд",          "SA_DT",  "GitHub, GitLab, Jenkins, IDE"),
        ("Cloud болон виртуал хөрөнгө",        "SA_CVA", "Cloud систем, cloud хадгалалт, SaaS, виртуал машин (VM)"),
    ]),
    ("Техник хангамжийн хөрөнгө", [
        ("Серверүүд",                  "HA_S",  "Өгөгдлийн сангийн сервер, вэб сервер, нөөцлөлтийн сервер"),
        ("Сүлжээний төхөөрөмжүүд",    "HA_ND", "Галт хана, чиглүүлэгч (router), switch, ачаалал тэнцвэржүүлэгч"),
        ("Хэрэглэгчийн төхөөрөмжүүд", "HA_UD", "Зөөврийн компьютер, суурин компьютер, гар утас, таблет"),
        ("Хадгалах төхөөрөмжүүд",     "HA_SD", "SAN, NAS, гадаад диск, USB төхөөрөмж"),
        ("IoT төхөөрөмжүүд",          "HA_ID", "IP камер, ухаалаг нэвтрэх хяналтын систем, принтер"),
    ]),
    ("Сүлжээ ба харилцаа холбоо", [
        ("Дотоод сүлжээ",               "NC_IN",  "LAN/WAN/VLAN тохиргоо"),
        ("Гадаад холболтууд",            "NC_EC",  "Интернет холболт, peering тохиргоо, cloud хандалт"),
        ("VPN дэд бүтэц",               "NC_VI",  "VPN concentrator, туннель, баталгаажуулалтын үйлчилгээ"),
        ("Харилцаа холбооны системүүд", "NC_CS",  "Имэйл сервер, VoIP систем, мессежийн платформ"),
        ("Домэйн үйлчилгээ",            "NC_DS",  "DNS, DHCP, Active Directory"),
        ("Сүлжээний тохиргоо ба дүрэм", "NC_NCR", "Routing table, галт ханын дүрэм, NAT тохиргоо"),
    ]),
    ("Хүний нөөцийн хөрөнгө", [
        ("Өндөр эрхтэй хэрэглэгчид",        "PA_PU", "Системийн администратор, root эрхтэй хэрэглэгч"),
        ("Ерөнхий хэрэглэгчид",             "PA_GU", "Ажилтнууд, түншүүд, дадлагажигчид"),
        ("Хөгжүүлэгчид",                    "PA_D",  "Дотоод эсвэл гуравдагч талын програм хангамжийн инженерүүд"),
        ("Удирдах ажилтнууд",               "PA_E",  "Гүйцэтгэх түвшний удирдлага, захирлууд"),
        ("Гэрээт ажилтан ба нийлүүлэгчид", "PA_CV", "Managed service provider, гадаад аудитор"),
        ("Аюулгүй байдлын баг",             "PA_ST", "SOC шинжээч, эрсдэлийн үнэлгээ хариуцсан ажилтан, нийцлийн ажилтан"),
    ]),
    ("Бодлого ба баримтжуулалт", [
        ("Бодлого, журам",              "PD_PP",  "Зохистой ашиглалтын журам, өгөгдөл хамгаалах журам, хандалтын хяналтын журам"),
        ("Төлөвлөгөөнүүд",             "PD_P",   "Зөрчлийн хариу арга хэмжээний төлөвлөгөө, гамшгийн дараах сэргээх төлөвлөгөө, бизнесийн тасралтгүй ажиллагааны төлөвлөгөө"),
        ("Сургалтын материал",          "PD_TM",  "Аюулгүй байдлын мэдлэг олгох сургалт, шинэ ажилтны чиглүүлэх гарын авлага"),
        ("Аудитын лог ба тайлан",       "PD_ALR", "Нийцлийн аудит, SOC тайлан"),
        ("Үйл ажиллагааны гэрээнүүд",  "PD_OC",  "Хөдөлмөрийн гэрээ (ажлын саналын захидал, өрсөлдөхгүй байх гэрээ), үл хөдлөх хөрөнгийн гэрээ (түрээсийн гэрээ, худалдан авах гэрээ), зээлийн гэрээ (хувийн зээлийн гэрээ, ипотекийн гэрээ), хэрэглэгчийн гэрээ (үйлчилгээний нөхцөл, баталгаа), технологийн гэрээ (програм хангамжийн лиценз, NDA)"),
    ]),
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
    {
        "slug": "zorchlin-burtgel",
        "table": "attachment_incidents",
        "entity_type": "attachment_incident",
        "title": "Хавсралт 4. Зөрчлийн бүртгэлийн загвар",
        "description": "Зөрчлийн удирдлагын дагуу бүртгэгдсэн зөрчлийн мэдээлэл.",
        "fields": [
            ("incident_id", "Incident ID", True, "auto"),
            ("detected_date", "Огноо (илэрсэн)", True, "text"),
            ("occurred_date", "Үүссэн (таамаг)", False, "text"),
            ("reported_by", "Мэдээлсэн", False, "text"),
            ("system_location", "Систем / Байршил", False, "text"),
            ("incident_type", "Төрөл", False, "text"),
            ("severity", "Severity", False, "select:Бага,Дунд,Өндөр,Маш өндөр"),
            ("l1_started", "L1 эхэлсэн", False, "text"),
            ("l2", "L2", False, "text"),
            ("l3", "L3", False, "text"),
            ("closed", "Хаасан", False, "text"),
            ("resolution_time", "Шийдвэрлэх хугацаа", False, "computed"),
            ("sla_violated", "SLA зөрчсөн", False, "select:Тийм,Үгүй"),
            ("root_cause", "Root Cause", False, "textarea"),
            ("description", "Тайлбар", False, "textarea"),
        ],
        "list_fields": [
            ("incident_id", "Incident ID"),
            ("detected_date", "Илэрсэн огноо"),
            ("system_location", "Систем / Байршил"),
            ("incident_type", "Төрөл"),
            ("severity", "Severity"),
            ("closed", "Хаасан"),
        ],
    },
]
DEFAULT_ADMIN_DOCUMENT_CATEGORIES = []
DEFAULT_USERS = []  # Local dept users removed; auth is Azure SSO only
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


def compute_asset_value(confidentiality, integrity_impact, availability_impact):
    c = ASSET_SCORE_MAP.get(confidentiality, 0)
    i = ASSET_SCORE_MAP.get(integrity_impact, 0)
    a = ASSET_SCORE_MAP.get(availability_impact, 0)
    if not (c and i and a):
        return ""
    return str(c + i + a)


def compute_asset_category(asset_value):
    try:
        v = int(asset_value)
        if 7 <= v <= 9:
            return "CAT1"
        if 4 <= v <= 6:
            return "CAT2"
        if 1 <= v <= 3:
            return "CAT3"
    except (ValueError, TypeError):
        pass
    return ""


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


def decode_portal_jwt(token):
    """Decode and verify a portal HS256 JWT. Returns payload dict or raises ValueError."""
    import base64
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("invalid structure")
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        secret = PORTAL_SSO_SECRET.encode("utf-8")
        expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        pad = lambda s: s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        actual_sig = base64.urlsafe_b64decode(pad(sig_b64))
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("invalid signature")
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)).decode("utf-8"))
        exp = payload.get("exp")
        if exp and dt.datetime.now(dt.timezone.utc).timestamp() > exp:
            raise ValueError("token expired")
        if not payload.get("email"):
            raise ValueError("missing email claim")
        return payload
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError(f"jwt error: {exc}") from exc


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


def _smtp_send(to_email, subject, body):
    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.attach(email.mime.text.MIMEText(body, "plain", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.sendmail(SMTP_USER, [to_email], msg.as_string())


def _send_async(to_email, subject, body):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        return
    threading.Thread(target=_smtp_send, args=(to_email, subject, body), daemon=True).start()


def create_auth_token(conn, user_id, token_type, expires_delta):
    token = secrets.token_urlsafe(32)
    expires_at = (now_utc() + expires_delta).isoformat()
    conn.execute(
        "INSERT INTO auth_tokens(user_id, token, token_type, expires_at, created_at) VALUES (?,?,?,?,?)",
        (user_id, token, token_type, expires_at, now_utc().isoformat()),
    )
    return token


def create_otp(conn, user_id):
    import random
    conn.execute("DELETE FROM auth_tokens WHERE user_id = ? AND token_type = 'otp'", (user_id,))
    code = f"{random.randint(0, 999999):06d}"
    expires_at = (now_utc() + dt.timedelta(minutes=15)).isoformat()
    conn.execute(
        "INSERT INTO auth_tokens(user_id, token, token_type, expires_at, created_at) VALUES (?,?,?,?,?)",
        (user_id, code, "otp", expires_at, now_utc().isoformat()),
    )
    return code


def consume_auth_token(conn, token, token_type):
    row = conn.execute(
        "SELECT * FROM auth_tokens WHERE token = ? AND token_type = ? AND used = 0",
        (token, token_type),
    ).fetchone()
    if not row:
        return None
    if _parse_dt(row["expires_at"]) < now_utc():
        return None
    conn.execute("UPDATE auth_tokens SET used = 1 WHERE id = ?", (row["id"],))
    return row


def send_invitation_email(conn, user_id, to_email, display_name):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        return
    conn.execute("DELETE FROM auth_tokens WHERE user_id = ? AND token_type = 'set_password'", (user_id,))
    token = create_auth_token(conn, user_id, "set_password", dt.timedelta(hours=24))
    link = APP_URL.rstrip("/") + "/set-password?token=" + token
    body = (
        "\u0421\u0430\u0439\u043d \u0431\u0430\u0439\u043d\u0430 \u0443\u0443,\n\n"
        "\u0422\u0430\u043d\u044b\u0433 \u043c\u044d\u0434\u044d\u044d\u043b\u043b\u044d\u043b\u0438\u0439\u043d "
        "\u0445\u04e9\u0440\u04e9\u043d\u0433\u0438\u0439\u043d \u0431\u04af\u0440\u0442\u0433\u044d\u043b "
        "\u0445\u0430\u0440\u0438\u0443\u0446\u0430\u043d \u0430\u0436\u0438\u043b\u043b\u0430\u0445 "
        "\u0430\u0436\u0438\u043b\u0442\u043d\u0430\u0430\u0440 Burtgel \u0441\u0438\u0441\u0442\u0435\u043c\u0434 "
        "\u0443\u0440\u044c\u0434\u0447\u0438\u043b\u0430\u043d \u0431\u04af\u0440\u0442\u0433\u044d\u0441\u044d\u043d "
        "\u0442\u0443\u043b \u0431\u04af\u0440\u0442\u0433\u044d\u043b \u04af\u04af\u0441\u0433\u044d\u0445 "
        "\u0443\u0440\u0438\u043b\u0433\u044b\u0433 \u0445\u04af\u0440\u0433\u04af\u04af\u043b\u0436 "
        "\u0431\u0430\u0439\u043d\u0430.\n\n"
        "\u0422\u0430 \u0434\u043e\u043e\u0440\u0445 \u0445\u043e\u043b\u0431\u043e\u043e\u0441\u043e\u043e\u0440 "
        "\u0445\u0430\u043d\u0434\u0430\u0436, \u04e9\u04e9\u0440\u0438\u0439\u043d "
        "\u0438-\u043c\u044d\u0439\u043b \u0445\u0430\u044f\u0433\u0430\u0430\u0440 \u0431\u04af\u0440\u0442\u0433\u044d\u043b "
        "\u04af\u04af\u0441\u0433\u044d\u043d \u0441\u0438\u0441\u0442\u0435\u043c\u0434 "
        "\u043d\u044d\u0432\u0442\u044d\u0440\u043d\u044d \u04af\u04af.\n\n"
        "\u041d\u044d\u0432\u0442\u0440\u044d\u0445 \u0445\u043e\u043b\u0431\u043e\u043e\u0441: " + link + "\n\n"
        "\u0425\u044d\u0440\u044d\u0432 \u043d\u044d\u0432\u0442\u0440\u044d\u0445\u044d\u0434 "
        "\u0430\u0441\u0443\u0443\u0434\u0430\u043b \u0433\u0430\u0440\u0432\u0430\u043b "
        "\u0441\u0438\u0441\u0442\u0435\u043c \u0430\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440\u0442\u043e\u0439 "
        "\u0445\u043e\u043b\u0431\u043e\u043e \u0431\u0430\u0440\u0438\u043d\u0430 \u0443\u0443.\n\n"
        "\u0411\u0430\u044f\u0440\u043b\u0430\u043b\u0430\u0430.")
    _send_async(to_email, "Burtgel - \u0421\u0438\u0441\u0442\u0435\u043c\u0434 \u043d\u044d\u043c\u044d\u0433\u0434\u0441\u044d\u043d \u0443\u0440\u0438\u043b\u0433\u0430", body)


def send_otp_email(to_email, display_name, otp_code):
    reset_link = APP_URL.rstrip("/") + "/reset-password?email=" + quote(to_email)
    greeting = "\u0421\u0430\u0439\u043d \u0431\u0430\u0439\u043d\u0430 \u0443\u0443, " + display_name + "!" if display_name else "\u0421\u0430\u0439\u043d \u0431\u0430\u0439\u043d\u0430 \u0443\u0443!"
    body = (greeting + "\n\n"
        "\u0422\u0430\u043d\u044b \u043d\u0443\u0443\u0446 \u04af\u0433 \u0441\u044d\u0440\u0433\u044d\u044d\u0445 "
        "\u043d\u044d\u0433 \u0443\u0434\u0430\u0430\u0433\u0438\u0439\u043d \u043a\u043e\u0434:\n\n  " + otp_code + "\n\n"
        "\u041a\u043e\u0434 15 \u043c\u0438\u043d\u0443\u0442\u044b\u043d \u0445\u0443\u0433\u0430\u0446\u0430\u0430\u043d\u0434 "
        "\u0445\u04af\u0447\u0438\u043d\u0442\u044d\u0439 \u0431\u0430\u0439\u043d\u0430.\n\n"
        "\u041d\u0443\u0443\u0446 \u04af\u0433 \u0448\u0438\u043d\u044d\u0447\u043b\u044d\u0445 \u0445\u043e\u043b\u0431\u043e\u043e\u0441:\n" + reset_link + "\n\n"
        "\u0425\u044d\u0440\u044d\u0432 \u0442\u0430 \u044d\u043d\u044d \u0445\u04af\u0441\u044d\u043b\u0442\u0438\u0439\u0433 "
        "\u04e9\u04e9\u0440\u04e9\u04e9 \u0438\u043b\u0433\u044d\u044d\u0433\u04af\u044d\u0439 \u0431\u043e\u043b "
        "\u044d\u043d\u044d \u0438-\u043c\u044d\u0439\u043b\u0438\u0439\u0433 \u04af\u043b \u0445\u044d\u0440\u044d\u0433\u0441\u044d\u043d\u044d \u04af\u04af.")
    _send_async(to_email, "Burtgel \u2014 \u041d\u0443\u0443\u0446 \u04af\u0433 \u0441\u044d\u0440\u0433\u044d\u044d\u0445 \u043a\u043e\u0434", body)


_MAX_XLSX_BYTES = 5 * 1024 * 1024   # 5 MB
_MAX_PDF_BYTES  = 20 * 1024 * 1024  # 20 MB


def _upload_too_large(field_storage, max_bytes):
    """Return True if the uploaded file exceeds max_bytes."""
    try:
        field_storage.file.seek(0, 2)
        size = field_storage.file.tell()
        field_storage.file.seek(0)
        return size > max_bytes
    except Exception:
        return False
def table_filter(table_id, placeholder="Хайх..."):
    """Renders a search input that client-side filters rows of a table by id."""
    return f"""
    <input type="search" class="table-filter-input" placeholder="{html.escape(placeholder)}"
      oninput="(function(v){{var rows=document.querySelectorAll('#{table_id} tbody tr');rows.forEach(function(r){{r.style.display=v&&!r.textContent.toLowerCase().includes(v.toLowerCase())?'none':''}})}})(this.value)"
      style="margin-bottom:12px">"""


def make_table_sortable(table_id, skip_last_cols=1):
    """Returns a <script> block that makes every column (except the last N) clickable to sort."""
    return f"""<script>
(function(){{
  var tbl=document.getElementById({json.dumps(table_id)});
  if(!tbl)return;
  var ths=tbl.tHead.rows[0].cells;
  var sortCol=-1,asc=true;
  var total=ths.length,sortable=total-{skip_last_cols};
  for(var i=0;i<sortable;i++){{
    (function(col){{
      var th=ths[col];
      th.classList.add('col-sortable');
      th.addEventListener('click',function(){{
        asc=(sortCol===col)?!asc:true;
        sortCol=col;
        for(var j=0;j<sortable;j++)ths[j].classList.remove('col-sort-asc','col-sort-desc');
        th.classList.add(asc?'col-sort-asc':'col-sort-desc');
        var tbody=tbl.tBodies[0];
        var rows=Array.from(tbody.rows);
        rows.sort(function(a,b){{
          var va=a.cells[col].textContent.trim();
          var vb=b.cells[col].textContent.trim();
          var na=parseFloat(va.replace(/[^0-9.\-]/g,'')),nb=parseFloat(vb.replace(/[^0-9.\-]/g,''));
          if(!isNaN(na)&&!isNaN(nb))return asc?na-nb:nb-na;
          return asc?va.localeCompare(vb,'mn'):vb.localeCompare(va,'mn');
        }});
        rows.forEach(function(r){{tbody.appendChild(r);}});
      }});
    }})(i);
  }}
}})();
</script>"""


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


_req = threading.local()


def parse_post(environ):
    cached = getattr(_req, "form_cache", None)
    if cached is not None:
        return cached
    try:
        size = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        size = 0
    raw = environ["wsgi.input"].read(size).decode("utf-8")
    result = {key: values[0] if values else "" for key, values in parse_qs(raw, keep_blank_values=True).items()}
    _req.form_cache = result
    return result


def parse_multipart(environ):
    env = {
        "REQUEST_METHOD": environ.get("REQUEST_METHOD", "POST"),
        "CONTENT_TYPE": environ.get("CONTENT_TYPE", ""),
        "CONTENT_LENGTH": environ.get("CONTENT_LENGTH", "0"),
    }
    return cgi.FieldStorage(fp=environ["wsgi.input"], environ=env, keep_blank_values=True)


def _csrf_token():
    return getattr(_req, "csrf_token", "")


def _set_csrf(session_id):
    _req.csrf_token = hmac.new(SECRET_KEY.encode(), session_id.encode(), "sha256").hexdigest()[:32]


def _verify_csrf(form):
    token = _csrf_token()
    submitted = form.get("_csrf", "")
    return bool(token) and hmac.compare_digest(token, submitted)


def _inject_csrf(body, token):
    hidden = f'<input type="hidden" name="_csrf" value="{token}">'
    return re.sub(
        r'(<form\b[^>]*\bmethod=["\']post["\'][^>]*>)',
        lambda m: m.group(0) + hidden,
        body,
        flags=re.IGNORECASE,
    )


def response(start_response, status, body, headers=None):
    token = _csrf_token()
    if token:
        body = _inject_csrf(body, token)
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
            expires_at TEXT NOT NULL,
            last_active_at TEXT
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

        CREATE TABLE IF NOT EXISTS attachment_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL DEFAULT '',
            detected_date TEXT NOT NULL DEFAULT '',
            occurred_date TEXT NOT NULL DEFAULT '',
            reported_by TEXT NOT NULL DEFAULT '',
            system_location TEXT NOT NULL DEFAULT '',
            incident_type TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT '',
            l1_started TEXT NOT NULL DEFAULT '',
            l2 TEXT NOT NULL DEFAULT '',
            l3 TEXT NOT NULL DEFAULT '',
            closed TEXT NOT NULL DEFAULT '',
            resolution_time TEXT NOT NULL DEFAULT '',
            sla_violated TEXT NOT NULL DEFAULT '',
            root_cause TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
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

        CREATE TABLE IF NOT EXISTS custom_register_brief_columns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            register_id INTEGER NOT NULL REFERENCES custom_registers(id) ON DELETE CASCADE,
            column_id INTEGER NOT NULL REFERENCES custom_register_columns(id) ON DELETE CASCADE,
            UNIQUE(register_id, column_id)
        );
        """
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            token_type TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    ensure_column(conn, "users", "last_login_at", "TEXT")
    ensure_column(conn, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "password_changed_at", "TEXT")
    ensure_column(conn, "users", "last_invited_at", "TEXT")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admin_document_subfiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_file_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            uploaded_at TEXT NOT NULL
        )
    """)
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
    ensure_column(conn, "sessions", "last_active_at", "TEXT")
    ensure_column(conn, "users", "email", "TEXT")
    ensure_column(conn, "users", "display_name", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "users", "last_invited_at", "TEXT")
    ensure_column(conn, "audit_logs", "actor_name", "TEXT")
    # Seed admin email from env if provided and not already set
    if ADMIN_EMAIL:
        conn.execute(
            "UPDATE users SET email = ? WHERE username = 'admin' AND (email IS NULL OR email = '')",
            (ADMIN_EMAIL.lower().strip(),),
        )
    conn.commit()
    seed_custom_register_samples(conn)
    seed_admin_document_categories(conn)
    conn.commit()
    conn.close()
    SUBFILES_DIR.mkdir(parents=True, exist_ok=True)


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


# ── Role helpers ─────────────────────────────────────────────
ROLE_SUPERADMIN = "superadmin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"

def user_role(user):
    if not user:
        return ROLE_USER
    try:
        r = user["role"]
    except (IndexError, KeyError):
        r = None
    return r or ROLE_USER

def is_superadmin(user):
    return user_role(user) == ROLE_SUPERADMIN

def is_admin_or_above(user):
    return user_role(user) in (ROLE_SUPERADMIN, ROLE_ADMIN)

def can_manage_users(user):
    return is_superadmin(user)

def _monthly_audit_table(ts=None):
    d = ts if ts else now_utc()
    return f"audit_logs_{d.strftime('%Y_%m')}"

def _ensure_monthly_audit_table(conn, table):
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            actor_name TEXT,
            target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)
    ensure_column(conn, table, "actor_name", "TEXT")

def record_audit(conn, actor_user_id, action, entity_type, entity_id=None, department_id=None, details="", target_user_id=None):
    ts = now_utc()
    table = _monthly_audit_table(ts)
    _ensure_monthly_audit_table(conn, table)
    actor_name = None
    if actor_user_id:
        row = conn.execute("SELECT display_name, email, username FROM users WHERE id = ?", (actor_user_id,)).fetchone()
        if row:
            actor_name = row["display_name"] or row["email"] or row["username"]
    vals = (actor_user_id, actor_name, target_user_id, department_id, action, entity_type, str(entity_id or ""), details, ts.isoformat())
    conn.execute(
        f"INSERT INTO {table}(actor_user_id, actor_name, target_user_id, department_id, action, entity_type, entity_id, details, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        vals,
    )
    # also keep legacy table in sync
    conn.execute(
        "INSERT INTO audit_logs(actor_user_id, actor_name, target_user_id, department_id, action, entity_type, entity_id, details, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        vals,
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
        SELECT sessions.id AS session_id, sessions.expires_at, sessions.last_active_at, users.*, departments.slug AS department_slug, departments.name AS department_name
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        LEFT JOIN departments ON departments.id = users.department_id
        WHERE sessions.id = ? AND users.is_active = 1
        """,
        (session_id,),
    ).fetchone()
    if not session_row:
        return None
    now = now_utc()
    if _parse_dt(session_row["expires_at"]) < now:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        return None
    last_active = session_row["last_active_at"]
    if last_active and (now - _parse_dt(last_active)) > dt.timedelta(minutes=60):
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        return None
    conn.execute("UPDATE sessions SET last_active_at = ? WHERE id = ?", (now.isoformat(), session_id))
    conn.commit()
    return session_row


def create_session(conn, user_id):
    session_id = secrets.token_urlsafe(32)
    now = now_utc()
    expires_at = (now + dt.timedelta(days=7)).isoformat()
    conn.execute(
        "INSERT INTO sessions(id, user_id, expires_at, last_active_at) VALUES (?, ?, ?, ?)",
        (session_id, user_id, expires_at, now.isoformat()),
    )
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
    if is_admin_or_above(user):
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
    if is_admin_or_above(user):
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
    if is_admin_or_above(user):
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
    return bool(user and (is_admin_or_above(user) or permissions.get(field_name, True)))

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


def get_custom_register_brief_column_ids(conn, register_id):
    rows = conn.execute(
        "SELECT column_id FROM custom_register_brief_columns WHERE register_id = ?",
        (register_id,),
    ).fetchall()
    return {row["column_id"] for row in rows}


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
def _public_docs_dropdown(conn):
    """Builds the 'Бичиг баримт' nav dropdown for all logged-in users."""
    try:
        cats = conn.execute(
            "SELECT id, name, slug FROM admin_document_categories ORDER BY display_order, name"
        ).fetchall()
        sub_items = ""
        for c in cats:
            if c["slug"] not in PUBLIC_DOC_CATEGORY_SLUGS:
                continue
            docs = conn.execute(
                "SELECT adcl.file_name FROM admin_document_category_links adcl "
                "WHERE adcl.category_id = ? ORDER BY adcl.file_name",
                (c["id"],),
            ).fetchall()
            count = len(docs)
            doc_links = "".join(
                f'<li><a class="dropdown-subitem" href="/admin-docs/{quote(d["file_name"])}">'
                f'{html.escape(d["file_name"])}</a></li>'
                for d in docs
            ) or '<li><span class="dropdown-subitem" style="color:var(--muted)">Файл алга</span></li>'
            sub_items += (
                f'<li class="nav-subdropdown">'
                f'<a class="dropdown-item dropdown-item-has-sub" href="/admin-doc-categories/{c["id"]}">'
                f'{html.escape(c["name"])} <span class="doc-count">({count})</span></a>'
                f'<ul class="nav-subdropdown-menu">{doc_links}</ul>'
                f'</li>'
            )
        if not sub_items:
            return ""
        return (
            '<li class="nav-dropdown">'
            '<a class="nav-dropdown-trigger" href="#">Бичиг баримт ▾</a>'
            f'<ul class="nav-dropdown-menu">{sub_items}</ul>'
            '</li>'
        )
    except Exception:
        return ""


def nav_links(user, conn=None):
    if not user:
        return ""
    role = user_role(user)
    items = []
    if role == ROLE_SUPERADMIN:
        items = [
            '<a href="/dashboard">Самбар</a>',
            '<a href="/departments">Хэлтсүүд</a>',
            '<a href="/users">Хэрэглэгчид</a>',
            '<a href="/kpi">KPI</a>',
            '<a href="/permissions">Эрх</a>',
            '<a href="/audit">Аудит</a>',
        ]
    elif role == ROLE_ADMIN:
        dept_slug = html.escape(user["department_slug"] or "")
        items = [
            '<a href="/dashboard">Самбар</a>',
            f'<a href="/departments/{dept_slug}/assets">Миний хэлтэс</a>' if dept_slug else '<a href="/departments">Хэлтэс</a>',
            '<a href="/kpi">KPI</a>',
            '<a href="/audit">Аудит</a>',
        ]
    else:  # user
        dept_slug = html.escape(user["department_slug"] or "")
        items = [
            f'<a href="/departments/{dept_slug}/assets">Хөрөнгийн бүртгэл</a>' if dept_slug else '<a href="/departments">Хэлтэс</a>',
        ]

    links_html = "".join(f"<li>{item}</li>" for item in items)

    # Public docs dropdown — visible to all logged-in users
    _own_conn = conn is None
    _c = conn if conn else get_db()
    try:
        links_html += _public_docs_dropdown(_c)
    except Exception:
        pass
    finally:
        if _own_conn:
            _c.close()

    return links_html


def render_page(title, user, content, notice="", conn=None):
    page_title = "МАБ Платформ"
    if user:
        role = user_role(user)
        dept_label = "Бүх хэлтэс" if role == ROLE_SUPERADMIN else html.escape(user["department_name"] or "-")
        display = html.escape(user["display_name"] or user["email"] or user["username"])
        nav_title = "МАБ Платформ" if role == ROLE_SUPERADMIN else "Хөрөнгийн Бүртгэл"
        topnav = f"""
  <nav class="topnav">
    <div class="nav-inner">
      <a href="/dashboard" class="nav-brand">
        <img src="{LOGO_ASSET_URL}" alt="logo" class="nav-logo">
        <span class="nav-title">{html.escape(nav_title)}</span>
      </a>
      <ul class="nav-links">{nav_links(user, conn)}</ul>
      <div class="nav-user">
        <button type="button" class="button-link ghost theme-toggle" id="theme-toggle" onclick="toggleTheme()">☀ Цайвар</button>
        <div class="user-chip">
          <strong>{display}</strong>
          <span>{dept_label}</span>
        </div>
        <form method="post" action="/logout" style="display:inline">
          <button type="submit" class="button-link ghost nav-logout">Гарах</button>
        </form>
      </div>
    </div>
  </nav>"""
        _wall = ""
        if is_admin_or_above(user):
            _wall_conn = conn
            _own_wall_conn = False
            if _wall_conn is None:
                try:
                    _wall_conn = get_db()
                    _own_wall_conn = True
                except Exception:
                    _wall_conn = None
            if _wall_conn:
                try:
                    _wall = docs_wall_html(user, _wall_conn)
                except Exception:
                    pass
                finally:
                    if _own_wall_conn:
                        _wall_conn.close()
        body_inner = f"""
  {topnav}
  {_wall}
  <div class="page-shell">
    <main class="main">
      {fmt_notice(notice)}
      {content}
    </main>
  </div>"""
    else:
        body_inner = f"""
  <div class="auth-shell">
    <div class="auth-brand">
      <img src="{LOGO_ASSET_URL}" alt="logo" class="nav-logo" style="height:40px">
    </div>
    <main class="auth-main">
      {fmt_notice(notice)}
      {content}
    </main>
  </div>"""
    return f"""<!doctype html>
<html lang="mn">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} | {html.escape(page_title)}</title>
  <script>
    (function() {{
      try {{
        var theme = localStorage.getItem('burtgel-theme') || 'light';
        document.documentElement.dataset.theme = theme;
      }} catch (error) {{
        document.documentElement.dataset.theme = 'light';
      }}
    }})();
  </script>
  <link rel="stylesheet" href="/static/styles.css">
  <link rel="icon" href="/favicon.ico" type="image/png">
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
    button.textContent = theme === 'light' ? '🌙 Харанхуй' : '☀ Цайвар';
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
function autoResizeTextarea(el) {{
  el.style.height = 'auto';
  el.style.height = el.scrollHeight + 'px';
}}
document.addEventListener('DOMContentLoaded', function() {{
  applyTheme(document.documentElement.dataset.theme || 'light');
  document.querySelectorAll('.kpi-cell-textarea').forEach(function(el) {{
    autoResizeTextarea(el);
    el.addEventListener('input', function() {{ autoResizeTextarea(el); }});
  }});
  (function() {{
    var path = window.location.pathname;
    var best = null, bestLen = 0;
    document.querySelectorAll('.nav-links a').forEach(function(a) {{
      var href = a.getAttribute('href');
      if (!href) return;
      if (path === href) {{ best = a; bestLen = href.length + 9999; return; }}
      if (href.length > 1 && path.startsWith(href) && href.length > bestLen) {{
        best = a; bestLen = href.length;
      }}
    }});
    if (best) best.classList.add('active');
  }})();
}});
function regSearch(input, regId) {{
  var q = input.value.trim().toLowerCase();
  var dd = document.getElementById('reg-search-dd-' + regId);
  if (!dd) return;
  if (q.length < 2) {{ dd.setAttribute('hidden', ''); dd.innerHTML = ''; return; }}
  var data = (window._regSearchData || {{}})[regId] || [];
  var results = [];
  for (var i = 0; i < data.length; i++) {{
    var row = data[i];
    for (var j = 0; j < row.cells.length; j++) {{
      var cell = row.cells[j];
      var val = cell.val || '';
      var idx = val.toLowerCase().indexOf(q);
      if (idx !== -1) {{
        results.push({{ num: row.num, id: row.id, col: cell.col, val: val, idx: idx, qlen: q.length }});
      }}
    }}
  }}
  if (!results.length) {{ dd.setAttribute('hidden', ''); dd.innerHTML = ''; return; }}
  var items = results.map(function(r, i) {{
    var before = r.val.substring(0, r.idx);
    var match  = r.val.substring(r.idx, r.idx + r.qlen);
    var after  = r.val.substring(r.idx + r.qlen);
    return '<div class="reg-search-item" data-row-id="' + r.id + '" data-reg-id="' + regId + '" onclick="regSearchGo(this)">'
      + '<span class="reg-search-row-num">#' + r.num + '</span>'
      + '<span class="reg-search-col">' + r.col.replace(/</g,'&lt;') + '</span>'
      + '<span class="reg-search-val">' + before.replace(/</g,'&lt;') + '<em>' + match.replace(/</g,'&lt;') + '</em>' + after.replace(/</g,'&lt;') + '</span>'
      + '</div>';
  }});
  dd.innerHTML = items.join('');
  dd.removeAttribute('hidden');
}}
function regSearchGo(item) {{
  var rowId = item.getAttribute('data-row-id');
  var card = document.querySelector('.reg-card[data-row-id="' + rowId + '"]');
  if (!card) return;
  card.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
  card.classList.remove('search-highlight');
  void card.offsetWidth;
  card.classList.add('search-highlight');
  card.addEventListener('animationend', function() {{ card.classList.remove('search-highlight'); }}, {{ once: true }});
}}
function regSearchHide(regId) {{
  var dd = document.getElementById('reg-search-dd-' + regId);
  if (dd) {{ dd.setAttribute('hidden', ''); }}
}}
function regSearchKey(e, regId) {{
  var dd = document.getElementById('reg-search-dd-' + regId);
  if (!dd || dd.hasAttribute('hidden')) return;
  var items = dd.querySelectorAll('.reg-search-item');
  var active = dd.querySelector('.reg-search-item.active');
  var idx = -1;
  items.forEach(function(el, i) {{ if (el === active) idx = i; }});
  if (e.key === 'ArrowDown') {{
    e.preventDefault();
    var next = items[idx + 1] || items[0];
    if (active) active.classList.remove('active');
    if (next) next.classList.add('active');
  }} else if (e.key === 'ArrowUp') {{
    e.preventDefault();
    var prev = items[idx - 1] || items[items.length - 1];
    if (active) active.classList.remove('active');
    if (prev) prev.classList.add('active');
  }} else if (e.key === 'Enter') {{
    if (active) {{ e.preventDefault(); regSearchGo(active); regSearchHide(regId); }}
  }} else if (e.key === 'Escape') {{
    regSearchHide(regId);
  }}
}}
</script>
  {body_inner}
</body>
</html>"""
def not_found(start_response):
    return response(start_response, "404 Not Found", render_page("Олдсонгүй", None, "<h1>Хуудас олдсонгүй</h1>"))


def forbidden(start_response):
    return response(start_response, "403 Forbidden", render_page("Хандах эрхгүй", None, "<h1>Хандах эрхгүй</h1>"))


def login_form(error="", notice=""):
    body = f"""
    <section class="panel panel-narrow auth-panel login-panel">
      <div class="login-logo-row">
        <img src="{LOGO_ASSET_URL}" alt="logo" style="height:48px">
      </div>
      <h1>Нэвтрэх</h1>
      {fmt_error(error)}
      {fmt_notice(notice)}
      <form method="post" action="/login" class="stack-form">
        <label>И-мэйл / хэрэглэгчийн нэр
          <input type="text" name="username" autocomplete="username" required autofocus>
        </label>
        <label>Нууц үг
          <input type="password" name="password" autocomplete="current-password" required>
        </label>
        <button type="submit">Нэвтрэх</button>
      </form>
      <p style="text-align:center;font-size:0.85rem"><a href="/forgot-password">Нууц үг мартсан уу?</a></p>
    </section>
    """
    return render_page("Нэвтрэх", None, body)


def set_password_page(token, error=""):
    body = f"""
    <section class="panel panel-narrow auth-panel">
      <div class="login-logo-row">
        <img src="{LOGO_ASSET_URL}" alt="logo" style="height:48px">
      </div>
      <h1>Нууц үг үүсгэх</h1>
      <p class="muted">Шинэ нууц үгээ оруулна уу.</p>
      {fmt_error(error)}
      <form method="post" action="/set-password" class="stack-form">
        <input type="hidden" name="token" value="{html.escape(token)}">
        <label>Шинэ нууц үг<input type="password" name="new_password" autocomplete="new-password" required autofocus></label>
        <label>Нууц үг давтах<input type="password" name="confirm_password" autocomplete="new-password" required></label>
        <button type="submit">Нууц үг үүсгэх</button>
      </form>
      <p class="helper">{html.escape(PASSWORD_POLICY_TEXT)}</p>
    </section>
    """
    return render_page("Нууц үг үүсгэх", None, body)


def forgot_password_page(error="", notice=""):
    body = f"""
    <section class="panel panel-narrow auth-panel">
      <div class="login-logo-row">
        <img src="{LOGO_ASSET_URL}" alt="logo" style="height:48px">
      </div>
      <h1>Нууц үг сэргээх</h1>
      <p class="muted">И-мэйл хаягаа оруулна уу. Нэг удаагийн код илгээнэ.</p>
      {fmt_error(error)}
      {fmt_notice(notice)}
      <form method="post" action="/forgot-password" class="stack-form">
        <label>И-мэйл хаяг<input type="email" name="email" autocomplete="email" required autofocus></label>
        <button type="submit">Код илгээх</button>
      </form>
      <a class="button-link ghost" href="/login">Буцах</a>
    </section>
    """
    return render_page("Нууц үг сэргээх", None, body)


def reset_password_page(email, error=""):
    body = f"""
    <section class="panel panel-narrow auth-panel">
      <div class="login-logo-row">
        <img src="{LOGO_ASSET_URL}" alt="logo" style="height:48px">
      </div>
      <h1>Шинэ нууц үг тохируулах</h1>
      <p class="muted">{html.escape(email)} хаягт илгээсэн 6 оронтой кодыг оруулна уу.</p>
      {fmt_error(error)}
      <form method="post" action="/reset-password" class="stack-form">
        <input type="hidden" name="email" value="{html.escape(email)}">
        <label>Нэг удаагийн код<input type="text" name="otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required autofocus></label>
        <label>Шинэ нууц үг<input type="password" name="new_password" autocomplete="new-password" required></label>
        <label>Нууц үг давтах<input type="password" name="confirm_password" autocomplete="new-password" required></label>
        <button type="submit">Нууц үг солих</button>
      </form>
      <p class="helper">{html.escape(PASSWORD_POLICY_TEXT)}</p>
      <a class="button-link ghost" href="/forgot-password">Код дахин авах</a>
    </section>
    """
    return render_page("Нууц үг солих", None, body)


def error_500_page():
    body = f"""
    <section class="panel panel-narrow auth-panel">
      <div class="login-logo-row">
        <img src="{LOGO_ASSET_URL}" alt="logo" style="height:48px">
      </div>
      <h1>Серверийн алдаа</h1>
      <p class="muted">Хүсэлт боловсруулахад алдаа гарлаа. Асуудал давтагдвал системийн администратортай холбоо барина уу.</p>
      <a class="button-link ghost" href="/login">Нэвтрэх хуудас руу буцах</a>
    </section>
    """
    return render_page("Серверийн алдаа", None, body)


def no_access_page():
    body = f"""
    <section class="panel panel-narrow auth-panel">
      <div class="login-logo-row">
        <img src="{LOGO_ASSET_URL}" alt="logo" style="height:48px">
      </div>
      <h1>Хандах эрхгүй</h1>
      <p class="muted">Таны Microsoft бүртгэл энэ системд бүртгэгдээгүй байна. Системд нэвтрэх эрх авахын тулд системийн администратортай холбоо барина уу.</p>
      <a class="button-link ghost" href="/login">Нэвтрэх хуудас руу буцах</a>
    </section>
    """
    return render_page("Хандах эрхгүй", None, body)


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
        if is_admin_or_above(user):
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
    title = "Бодлого, журам" if not is_admin_or_above(user) else "Хэрэглэгчдэд харагдах PDF баримтууд"
    description = "Эдгээр PDF баримтуудыг систем дээрээс шууд үзэж болно." if not is_admin_or_above(user) else "Админ эдгээр PDF баримтыг нэмж, шинэчилж, устгаж болно."
    create_form = ""
    if is_admin_or_above(user):
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
    superadmin = is_superadmin(user)
    for department in departments_for_user(conn, user):
        count = conn.execute("SELECT COUNT(*) FROM assets WHERE department_id = ?", (department["id"],)).fetchone()[0]
        manage_btns = ""
        if superadmin:
            manage_btns = f"""
              <div class="action-strip" style="margin-top:0.5rem">
                <a class="button-link ghost small" href="/departments/{html.escape(department['slug'])}/edit">Засах</a>
                <form method="post" action="/departments/{html.escape(department['slug'])}/delete" style="display:inline"
                      onsubmit="return confirm('{html.escape(department['name'])} хэлтсийг устгах уу? Бүх хөрөнгө устна.')">
                  <button type="submit" class="button-link ghost small danger">Устгах</button>
                </form>
              </div>"""
        cards.append(
            f"""
            <article class="card">
              <h2>{html.escape(department['name'])}</h2>
              <p class="muted" style="font-size:0.8em">{html.escape(department['code'])}</p>
              <p>{count} хөрөнгө</p>
              <a class="button-link" href="/departments/{html.escape(department['slug'])}/assets">Бүртгэл нээх</a>
              {manage_btns}
            </article>
            """
        )
    page_title = "Хэлтсүүдийн хөрөнгө" if is_admin_or_above(user) else "Мэдээллийн хөрөнгийн нэгдсэн бүртгэл"
    page_description = "Хэрэглэгч өөрийн харьяалах хэлтсийн хөрөнгийг, админ бүх хэлтсийн хөрөнгийг энэ хэсгээс нээнэ." if is_admin_or_above(user) else "Өөрийн харьяалах хэлтсийн мэдээллийн хөрөнгийн бүртгэлийг энэ хэсгээс нээнэ."
    add_btn = '<a class="button-link" href="/departments/create">+ Хэлтэс нэмэх</a>' if superadmin else ""
    heading_row = f"""
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem">
        <div>
          <h1>{html.escape(page_title)}</h1>
          <p class="muted">{html.escape(page_description)}</p>
        </div>
        {add_btn}
      </div>"""
    body = f"""
    <section class="panel">
      {heading_row}
      <div class="card-grid" style="margin-top:1rem">{''.join(cards) if cards else '<p>Энэ хэрэглэгчид хэлтэс оноогоогүй байна.</p>'}</div>
    </section>
    {render_reference_documents_section(user)}
    """
    return render_page(page_title, user, body, notice)


def department_create_page(error="", values=None):
    values = values or {}
    body = f"""
    <section class="panel">
      <h1>Шинэ хэлтэс нэмэх</h1>
      {fmt_error(error)}
      <form method="post" action="/departments/create" class="stack-form">
        <label>Хэлтсийн нэр
          <input type="text" name="name" value="{html.escape(values.get('name', ''))}" required maxlength="200" placeholder="Жишээ: Мэдээллийн технологийн хэлтэс">
        </label>
        <label>Код (товч)
          <input type="text" name="code" value="{html.escape(values.get('code', ''))}" required maxlength="30" placeholder="Жишээ: IT">
        </label>
        <div class="form-actions">
          <button type="submit" class="button-link">Нэмэх</button>
          <a class="button-link ghost" href="/departments">Буцах</a>
        </div>
      </form>
    </section>
    """
    return body


def department_edit_page(department, error="", values=None):
    values = values or {}
    name_val = values.get("name", department["name"])
    code_val = values.get("code", department["code"])
    body = f"""
    <section class="panel">
      <h1>Хэлтэс засах</h1>
      {fmt_error(error)}
      <form method="post" action="/departments/{html.escape(department['slug'])}/edit" class="stack-form">
        <label>Хэлтсийн нэр
          <input type="text" name="name" value="{html.escape(name_val)}" required maxlength="200">
        </label>
        <label>Код (товч)
          <input type="text" name="code" value="{html.escape(code_val)}" required maxlength="30">
        </label>
        <div class="form-actions">
          <button type="submit" class="button-link">Хадгалах</button>
          <a class="button-link ghost" href="/departments">Буцах</a>
        </div>
      </form>
    </section>
    """
    return body


def _audit_sidebar(conn):
    rows = conn.execute(
        """
        SELECT audit_logs.created_at, actor.username AS actor_username,
               actor.display_name AS actor_display_name,
               audit_logs.actor_name, audit_logs.action, audit_logs.details
        FROM audit_logs
        LEFT JOIN users AS actor ON actor.id = audit_logs.actor_user_id
        ORDER BY audit_logs.created_at DESC, audit_logs.id DESC
        LIMIT 20
        """
    ).fetchall()
    action_label_map = {
        "login": "Нэвтэрсэн", "logout": "Гарсан", "login_failed": "Нэвтрэх амжилтгүй",
        "change_password": "Нууц үг солилт",
        "reset_password": "Нууц үг reset", "create": "Үүсгэсэн", "update": "Засварласан",
        "delete": "Устгасан", "update_permissions": "Эрх өөрчлөлт", "invite": "Урилга илгэсэн",
    }
    items = []
    for row in rows:
        label = action_label_map.get(row["action"], row["action"])
        items.append(
            f'<div class="audit-feed-item">'
            f'<div class="audit-feed-meta"><span class="audit-feed-actor">{html.escape(row["actor_display_name"] or row["actor_username"] or row["actor_name"] or "Систем")}</span>'
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
    role = user_role(user)
    if role == ROLE_SUPERADMIN:
        total_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        total_depts = conn.execute("SELECT COUNT(*) FROM departments").fetchone()[0]
        total_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
        recent_changes = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE updated_at >= datetime('now', '-7 days')"
        ).fetchone()[0]
        stat_cards = f"""
        <div class="stat-grid">
          <div class="stat-card">
            <div class="stat-label">Нийт хөрөнгө</div>
            <div class="stat-value">{total_assets}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Хэлтэс</div>
            <div class="stat-value">{total_depts}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Хэрэглэгч</div>
            <div class="stat-value">{total_users}</div>
            <div class="stat-sub">идэвхтэй</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Өөрчлөлт</div>
            <div class="stat-value">{recent_changes}</div>
            <div class="stat-sub">сүүлийн 7 хоног</div>
          </div>
        </div>
        """
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
        </div>
        {stat_cards}
        {kpi_section}
        {render_custom_registers_overview(conn)}
        """
        body = f"""
        <div class="dashboard-admin-grid">
          <div class="dashboard-main">{main_html}</div>
          {_audit_sidebar(conn)}
        </div>
        """
        return render_page("Хяналтын самбар", user, body, notice)
    if role == ROLE_ADMIN:
        dept_id = user["department_id"]
        dept_assets = conn.execute("SELECT COUNT(*) FROM assets WHERE department_id = ?", (dept_id,)).fetchone()[0] if dept_id else 0
        recent_dept = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE department_id = ? AND updated_at >= datetime('now', '-7 days')", (dept_id,)
        ).fetchone()[0] if dept_id else 0
        dept_name = html.escape(user["department_name"] or "—")
        stat_cards = f"""
        <div class="stat-grid">
          <div class="stat-card">
            <div class="stat-label">{dept_name}</div>
            <div class="stat-value">{dept_assets}</div>
            <div class="stat-sub">нийт хөрөнгө</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Өөрчлөлт</div>
            <div class="stat-value">{recent_dept}</div>
            <div class="stat-sub">сүүлийн 7 хоног</div>
          </div>
        </div>
        """
        dept_slug = html.escape(user["department_slug"] or "")
        dept_link = f'<a class="button-link ghost" href="/departments/{dept_slug}/assets">Хэлтсийн бүртгэл</a>' if dept_slug else ""
        main_html = f"""
        <div class="dashboard-page-header">
          <span class="dashboard-title-sm">Хяналтын самбар</span>
          {dept_link}
        </div>
        {stat_cards}
        {render_custom_registers_overview(conn)}
        """
        return render_page("Хяналтын самбар", user, main_html, notice)
    # ROLE_USER — redirect to their dept
    dept_slug = user["department_slug"] or ""
    if dept_slug:
        body = f'<meta http-equiv="refresh" content="0;url=/departments/{html.escape(dept_slug)}/assets">'
        return render_page("Хяналтын самбар", user, body, notice)
    body = """
    <section class="panel">
      <h1>Тавтай морил</h1>
      <p class="muted">Таны бүртгэлд хэлтэс оноогдоогүй байна. Администратортай холбоо барина уу.</p>
    </section>
    """
    return render_page("Хяналтын самбар", user, body, notice)
def _render_kod_modal():
    rows = []
    for type_name, subtypes in KOD_TABLE_DATA:
        first = True
        for subtype, code, examples in subtypes:
            if first:
                type_cell = f'<td class="kod-type-cell" rowspan="{len(subtypes)}">{html.escape(type_name)}</td>'
                first = False
            else:
                type_cell = ""
            rows.append(
                f'<tr>{type_cell}'
                f'<td>{html.escape(subtype)}</td>'
                f'<td><code>{html.escape(code)}</code></td>'
                f'<td class="kod-examples">{html.escape(examples)}</td>'
                f'</tr>'
            )
    table = (
        '<table class="kod-ref-table">'
        '<thead><tr><th>Төрөл</th><th>Дэд төрөл</th><th>Хөрөнгийн код</th><th>Жишээ</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        '</table>'
    )
    return (
        '<div id="kod-desc-modal" class="kod-overlay" hidden>'
        '<div class="kod-modal" role="dialog" aria-modal="true">'
        '<div class="kod-modal-header">'
        '<h3>Кодын тайлбар</h3>'
        '<button type="button" class="kod-modal-close" id="kod-modal-close-btn">✕</button>'
        '</div>'
        f'<div class="kod-modal-body">{table}</div>'
        '</div>'
        '</div>'
        '<script>'
        '(function(){'
        'var overlay=document.getElementById("kod-desc-modal");'
        'var closeBtn=document.getElementById("kod-modal-close-btn");'
        'function closeModal(){overlay.hidden=true;}'
        'closeBtn.addEventListener("click",closeModal);'
        'overlay.addEventListener("click",function(e){'
        'if(e.target===overlay){closeModal();return;}'
        'var codeEl=e.target.closest("code");'
        'if(codeEl){'
        'var code=codeEl.textContent.trim();'
        'var sel=document.querySelector(\'select[name="asset_group_code"]\');'
        'if(sel){sel.value=code;sel.dispatchEvent(new Event("change",{bubbles:true}));}'
        'closeModal();'
        '}'
        '});'
        'document.addEventListener("keydown",function(e){if(e.key==="Escape"&&!overlay.hidden)closeModal();});'
        '})();'
        '</script>'
    )


def _render_review_frequency_field(user, source):
    current = html.escape(source.get("review_frequency", "") or "")
    if is_admin_or_above(user):
        options = '<option value="">— Сонгоно уу —</option>'
        for opt in FREQUENCY_OPTIONS:
            sel = "selected" if source.get("review_frequency") == opt else ""
            options += f'<option value="{html.escape(opt)}" {sel}>{html.escape(opt)}</option>'
        return f'<label>Хянах давтамж<select name="review_frequency">{options}</select></label>'
    val = source.get("review_frequency") or "—"
    return f'<label>Хянах давтамж<input type="text" value="{html.escape(val)}" readonly><span class="helper">Энэ талбарыг зөвхөн админ өөрчилнө.</span></label>'


def _render_asset_field(name, label, required, source, user, permissions):
    value = source.get(name, "") or ""
    is_computed = name in ASSET_COMPUTED_FIELDS
    editable = (not is_computed) and can_edit_field(user, permissions, name)
    required_attr = " required" if required and editable else ""
    _wide_fields = {"description", "location", "integrity_impact", "availability_impact"}
    _textarea_fields = {"description", "location"}
    extra_class = ' class="col-span-2"' if name in _wide_fields else ''

    if is_computed:
        helper = '<span class="helper">Автоматаар тооцоологдоно.</span>'
        field = f'<input type="text" id="computed_{name}" name="{name}" value="{html.escape(str(value))}" readonly>'
        return f'<label{extra_class}>{html.escape(label)}{field}{helper}</label>'

    if name in DROPDOWN_OPTIONS:
        opts_html = '<option value="">— Сонгоно уу —</option>'
        for opt in DROPDOWN_OPTIONS[name]:
            if isinstance(opt, tuple):
                opt_label, opt_value = opt
            else:
                opt_label = opt_value = opt
            sel = " selected" if opt_value == value else ""
            score = ASSET_SCORE_MAP.get(opt_value, 0)
            score_attr = f' data-score="{score}"' if name in ASSET_SCORE_FIELDS else ""
            opts_html += f'<option value="{html.escape(str(opt_value))}"{sel}{score_attr}>{html.escape(str(opt_label))}</option>'
        disabled_attr = " disabled" if not editable else ""
        helper = '<span class="helper">Зөвхөн админ өөрчилнө.</span>' if not editable else ''
        field = f'<select name="{name}"{required_attr}{disabled_attr}>{opts_html}</select>'
        if not editable:
            field += f'<input type="hidden" name="{name}" value="{html.escape(str(value))}">'
        if name == "asset_group_code":
            label_html = (
                f'<span class="label-with-action">'
                f'{html.escape(label)}'
                f'<button type="button" class="kod-help-btn" '
                f'onclick="document.getElementById(\'kod-desc-modal\').hidden=false">Кодын тайлбар</button>'
                f'</span>'
            )
        else:
            label_html = html.escape(label)
        return f'<label{extra_class}>{label_html}{field}{helper}</label>'

    readonly_attr = " readonly" if not editable else ""
    helper = '<span class="helper">Зөвхөн админ өөрчилнө.</span>' if not editable else ''
    if name in _textarea_fields:
        field = f'<textarea name="{name}"{required_attr}{readonly_attr}>{html.escape(str(value))}</textarea>'
    else:
        field = f'<input type="text" name="{name}" value="{html.escape(str(value))}"{required_attr}{readonly_attr}>'
    return f'<label{extra_class}>{html.escape(label)}{field}{helper}</label>'


def render_asset_form(action, user, department, values, permissions, error="", submit_label="Хадгалах"):
    source = dict(values) if values else {}
    _section_starts = {
        "asset_name": "Үндсэн мэдээлэл",
        "has_personal_data": "Ангилал ба аюулгүй байдал",
        "owner": "Эзэмшил ба байршил",
    }

    sections_html = []
    cur_items = []
    cur_title = None

    for name, label, required in ASSET_FIELDS:
        if name in _section_starts:
            if cur_title is not None:
                sections_html.append(
                    f'<div class="form-section">'
                    f'<div class="form-section-header">{cur_title}</div>'
                    f'<div class="form-section-body">{"".join(cur_items)}</div>'
                    f'</div>'
                )
            cur_title = _section_starts[name]
            cur_items = []
        cur_items.append(_render_asset_field(name, label, required, source, user, permissions))

    if cur_title is not None:
        sections_html.append(
            f'<div class="form-section">'
            f'<div class="form-section-header">{cur_title}</div>'
            f'<div class="form-section-body">{"".join(cur_items)}</div>'
            f'</div>'
        )

    score_js = """
<script>
(function() {
  var scoreFields = ['confidentiality', 'integrity_impact', 'availability_impact'];
  function recalc() {
    var total = 0, allSet = true;
    scoreFields.forEach(function(f) {
      var sel = document.querySelector('select[name="' + f + '"]');
      if (!sel) return;
      var opt = sel.options[sel.selectedIndex];
      var score = opt ? parseInt(opt.getAttribute('data-score') || '0', 10) : 0;
      if (score > 0) total += score; else allSet = false;
    });
    var valEl = document.getElementById('computed_asset_value');
    var catEl = document.getElementById('computed_asset_category');
    if (valEl) valEl.value = allSet ? total : '';
    if (catEl) {
      if (!allSet) catEl.value = '';
      else if (total >= 7) catEl.value = 'CAT1';
      else if (total >= 4) catEl.value = 'CAT2';
      else catEl.value = 'CAT3';
    }
  }
  scoreFields.forEach(function(f) {
    var sel = document.querySelector('select[name="' + f + '"]');
    if (sel) sel.addEventListener('change', recalc);
  });
  recalc();
})();
</script>"""

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
        {''.join(sections_html)}
        <div class=\"review-section\">
          <h3 class=\"review-section-title\">Хяналтын тохиргоо</h3>
          {_render_review_frequency_field(user, source)}
        </div>
        <div class=\"actions\"><button type=\"submit\">{submit_label}</button></div>
      </form>
      {_render_kod_modal()}
      {score_js}
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
      {table_filter("asset-table", "Хөрөнгийн нэр, төрөл, эзэмшигч хайх...")}
      <div class=\"table-wrap\">
        <table id="asset-table">
          <thead>
            <tr>{''.join(f'<th>{label}</th>' for _, label in LIST_FIELDS)}<th>Үлдсэн хугацаа</th><th></th></tr>
          </thead>
          <tbody>
            {''.join(body_rows) if body_rows else '<tr><td colspan="8">Энэ хэлтэст одоогоор хөрөнгө бүртгэгдээгүй байна.</td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
    {make_table_sortable("asset-table", skip_last_cols=1)}
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


def admin_reset_password_page(user, target_user, error="", notice="", temp_password=""):
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
        SELECT users.id, users.username, users.email, users.display_name,
               users.is_admin, users.role, users.is_active, users.last_login_at,
               users.last_invited_at, departments.name AS department_name
        FROM users
        LEFT JOIN departments ON departments.id = users.department_id
        ORDER BY users.is_admin DESC, users.username
        """
    ).fetchall()
    _role_labels = {ROLE_SUPERADMIN: "Супер Админ", ROLE_ADMIN: "Админ", ROLE_USER: "Хэрэглэгч"}
    now = now_utc()
    rows = []
    for row in user_rows:
        dept = row["department_name"] or "—"
        role_val = row["role"] or (ROLE_ADMIN if row["is_admin"] else ROLE_USER)
        role = _role_labels.get(role_val, role_val)
        active_label = "Идэвхтэй" if row["is_active"] else '<span style="color:var(--danger)">Идэвхгүй</span>'
        email_cell = html.escape(row["email"] or "—")
        is_self = row["id"] == user["id"]
        delete_btn = (
            f'<form method="post" action="/users/{row["id"]}/delete" style="display:inline" onsubmit="return confirm(\'{html.escape(row["email"] or row["username"])} хэрэглэгчийг устгах уу?\')"><button class="button-link ghost small danger" type="submit">Устгах</button></form>'
            if not is_self else ""
        )
        invite_btn = ""
        otp_btn = ""
        if row["email"] and SMTP_HOST:
            last_inv = row["last_invited_at"]
            cooldown_ok = not last_inv or (now - _parse_dt(last_inv)).total_seconds() > 600
            if cooldown_ok:
                label = "Урилга илгээх" if not last_inv else "Дахин илгээх"
                invite_btn = (
                    f'<form method="post" action="/users/{row["id"]}/invite" style="display:inline">'
                    f'<button class="button-link ghost small" type="submit">{label}</button></form>'
                )
            else:
                invite_btn = '<button class="button-link ghost small" disabled title="10 минутын дараа дахин илгээх боломжтой">Илгэгдсэн ✓</button>'
            if row["is_active"]:
                otp_btn = (
                    f'<form method="post" action="/users/{row["id"]}/send-otp" style="display:inline"'
                    f' onsubmit="return confirm(\'OTP нууц үг сэргээх код илгээх үү?\')">'
                    f'<button class="button-link ghost small" type="submit">OTP илгээх</button></form>'
                )
        rows.append(
            f"""
            <tr>
              <td>{html.escape(row['display_name'] or row['username'])}</td>
              <td class="muted">{email_cell}</td>
              <td>{html.escape(dept)}</td>
              <td>{role}</td>
              <td>{active_label}</td>
              <td>{format_dt(row['last_login_at'])}</td>
              <td class="table-actions">
                <div class="action-strip">
                  <a class="button-link ghost small" href="/users/{row['id']}/edit">Засах</a>
                  {invite_btn}
                  {otp_btn}
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
      {table_filter("users-table", "Нэр, и-мэйл, хэлтэс хайх...")}
      <div class="table-wrap">
        <table id="users-table">
          <thead>
            <tr>
              <th>Нэр</th>
              <th>И-мэйл (Azure)</th>
              <th>Хэлтэс</th>
              <th>Эрх</th>
              <th>Төлөв</th>
              <th>Сүүлд нэвтэрсэн</th>
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
    dept_options = '<option value="">— Хэлтэс сонгоогүй —</option>'
    for d in departments:
        sel = 'selected' if str(values.get("department_id", "")) == str(d["id"]) else ""
        dept_options += f'<option value="{d["id"]}" {sel}>{html.escape(d["name"])}</option>'
    sel_role = values.get("role", ROLE_USER)
    role_options = "".join(
        f'<option value="{r}" {"selected" if sel_role == r else ""}>{lbl}</option>'
        for r, lbl in [(ROLE_USER, "Хэрэглэгч"), (ROLE_ADMIN, "Админ"), (ROLE_SUPERADMIN, "Супер Админ")]
    )
    body = f"""
    <section class="panel panel-narrow">
      <h1>Шинэ хэрэглэгч нэмэх</h1>
      {fmt_error(error)}
      <form method="post" action="/users/create" class="stack-form">
        <label>Azure и-мэйл хаяг<input type="email" name="email" value="{html.escape(values.get('email', ''))}" required autofocus placeholder="user@company.com"></label>
        <label>Дэлгэцийн нэр (заавал биш)<input type="text" name="display_name" value="{html.escape(values.get('display_name', ''))}" placeholder="Нэр Овог"></label>
        <label>Үндсэн хэлтэс
          <select name="department_id">{dept_options}</select>
        </label>
        <label>Эрхийн түвшин
          <select name="role">{role_options}</select>
        </label>
        <p class="muted" style="margin:0">Хэрэглэгч порталаар нэвтэрч орно. Нууц үг шаардлагагүй.</p>
        <div style="display:flex;gap:0.5rem">
          <button type="submit">Үүсгэх</button>
          <a class="button-link ghost" href="/users">Буцах</a>
        </div>
      </form>
    </section>
    """
    return body


def user_edit_page(conn, target_user, departments, dept_perms, error="", values=None):
    # Normalise target_user to dict so .get() works everywhere below
    tu = dict(target_user) if not isinstance(target_user, dict) else target_user
    values = values or tu
    dept_options = '<option value="">— Хэлтэс сонгоогүй —</option>'
    selected_dept = str(values.get("department_id") or tu.get("department_id") or "")
    for d in departments:
        sel = 'selected' if str(d["id"]) == selected_dept else ""
        dept_options += f'<option value="{d["id"]}" {sel}>{html.escape(d["name"])}</option>'
    cur_role = (values.get("role") if values is not tu else None) or tu.get("role") or (ROLE_ADMIN if tu.get("is_admin") else ROLE_USER)
    role_options = "".join(
        f'<option value="{r}" {"selected" if cur_role == r else ""}>{lbl}</option>'
        for r, lbl in [(ROLE_USER, "Хэрэглэгч"), (ROLE_ADMIN, "Админ"), (ROLE_SUPERADMIN, "Супер Админ")]
    )
    is_active_checked = 'checked' if (values.get("is_active", "1") != "0" if values is not tu else tu.get("is_active")) else ""

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

    edit_email = html.escape(str(values.get("email") or tu.get("email") or ""))
    edit_display = html.escape(str(values.get("display_name") or tu.get("display_name") or ""))
    body = f"""
    <section class="panel panel-narrow">
      <h1>{html.escape(tu.get('display_name') or tu.get('email') or tu.get('username',''))} — Засах</h1>
      {fmt_error(error)}
      <form method="post" action="/users/{target_user['id']}/edit" class="stack-form">
        <label>Azure и-мэйл хаяг<input type="email" name="email" value="{edit_email}" required></label>
        <label>Дэлгэцийн нэр<input type="text" name="display_name" value="{edit_display}" placeholder="Нэр Овог"></label>
        <label>Хэлтэс (үндсэн)
          <select name="department_id">{dept_options}</select>
        </label>
        <label>Эрхийн түвшин
          <select name="role">{role_options}</select>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" name="is_active" value="1" {is_active_checked}> Идэвхтэй
        </label>
        <h2 style="margin-top:1.5rem">Хэлтсийн хандах эрх</h2>
        <p class="muted" style="margin:0">Админ болон Супер Админ эрхтэй хэрэглэгчид бүх хэлтэст автоматаар хандана.</p>
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
            <textarea name="indicator" class="kpi-cell-input kpi-cell-textarea" rows="1">{html.escape(item['indicator'])}</textarea>
          </td>
          <td><textarea name="description" class="kpi-cell-input kpi-cell-textarea" rows="1">{html.escape(item['description'])}</textarea></td>
          <td><textarea name="formula" class="kpi-cell-input kpi-cell-textarea" rows="1">{html.escape(item['formula'])}</textarea></td>
          <td><input type="text" name="target_level" value="{html.escape(item['target_level'])}" class="kpi-cell-input"></td>
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
      <form method="post" action="/kpi/{html.escape(directory['slug'])}/rows/new" style="display:contents">
      <td class="muted">*</td>
      <td><textarea name="indicator" class="kpi-cell-input kpi-cell-textarea" rows="1" placeholder="Шалгуур үзүүлэлт" required></textarea></td>
      <td><textarea name="description" class="kpi-cell-input kpi-cell-textarea" rows="1" placeholder="Тайлбар"></textarea></td>
      <td><textarea name="formula" class="kpi-cell-input kpi-cell-textarea" rows="1" placeholder="Хэмжих нэгж / Томьёо"></textarea></td>
      <td><input type="text" name="target_level" class="kpi-cell-input" placeholder="Зорилт"></td>
      <td><select name="frequency" class="kpi-cell-select"><option value="">— сонго —</option>{freq_options}</select></td>
      <td><input type="date" name="due_date" class="kpi-cell-input"></td>
      <td>—</td>
      <td><button class="button-link small" type="submit">+ Нэмэх</button></td>
      </form>
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
              <th style="width:3%">№</th>
              <th style="width:18%">Гүйцэтгэлийн шалгуур үзүүлэлт</th>
              <th style="width:24%">Тайлбар</th>
              <th style="width:11%">Хэмжих нэгж / Томьёо</th>
              <th style="width:9%">Зорилтот түвшин</th>
              <th style="width:10%">Хянах давтамж</th>
              <th style="width:11%">Дуусах өдөр</th>
              <th style="width:5%">Үлдсэн хугацаа</th>
              <th style="width:9%"></th>
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
    items = []
    manage_rows = []
    for register in list_custom_registers(conn):
        slug = html.escape(register["slug"])
        items.append(
            f'<li class="item-list-row">'
            f'<span class="item-list-label"><a href="/custom-registers/{slug}">{html.escape(register["title"])}</a></span>'
            f'<div class="action-strip">'
            f'<a class="button-link ghost small" href="/custom-registers/{slug}/export.xlsx">Excel</a>'
            f'<a class="button-link ghost small" href="/custom-registers/{slug}/export.pdf">PDF</a>'
            f'</div></li>'
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
    list_html = (
        f'<ul class="item-list">{"".join(items)}</ul>'
        if items else
        '<p class="muted">Одоогоор бүртгэл алга.</p>'
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
      {list_html}
    </section>
    """


def custom_register_row_detail_page(user, register, columns, row, values):
    items = []
    for column in columns:
        items.append(
            f"""
            <article class="detail-item">
              <div class="detail-label">{html.escape(column['name'])}</div>
              <div class="detail-value">{format_multiline(values.get(column['slug'], ''))}</div>
            </article>
            """
        )
    items.append(
        f"""
        <article class="detail-item">
          <div class="detail-label">Сүүлд өөрчилсөн</div>
          <div class="detail-value">{format_dt(row['updated_at'])}</div>
        </article>
        """
    )
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(register['title'])}</h1>
          <p class="muted">Мөрийн дэлгэрэнгүй мэдээлэл.</p>
        </div>
        <div class="action-strip">
          <a class="button-link ghost" href="/custom-registers/{html.escape(register['slug'])}">Буцах</a>
          <a class="button-link ghost" href="/custom-registers/{html.escape(register['slug'])}/rows/{row['id']}/edit">Засах</a>
        </div>
      </div>
      <div class="detail-grid">{''.join(items)}</div>
    </section>
    """
    return render_page(register["title"], user, body)


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
    brief_col_ids = get_custom_register_brief_column_ids(conn, register["id"])
    manage_toggle_id = f"custom-register-column-manage-{register['id']}"
    add_row_toggle_id = f"custom-register-add-row-{register['id']}"
    reg_slug = html.escape(register["slug"])

    # Manage columns panel
    manage_rows = []
    for column in columns:
        brief_checked = " checked" if column["id"] in brief_col_ids else ""
        manage_rows.append(
            f"""
            <tr>
              <td>{html.escape(column['name'])}</td>
              <td>
                <form method="post" action="/custom-registers/{reg_slug}/columns/{column['id']}/rename" class="inline-form inline-rename-form split-rename-form">
                  <input type="text" name="name" value="{html.escape(column['name'])}" class="table-inline-input compact-input" required>
                  <button type="submit" class="button-link ghost small">Нэр хадгалах</button>
                </form>
              </td>
              <td>
                <form method="post" action="/custom-registers/{reg_slug}/columns/{column['id']}/brief-toggle" class="inline-form">
                  <input type="checkbox" name="enabled" value="1"{brief_checked} onchange="this.form.submit()">
                </form>
              </td>
              <td class="table-actions">
                <form method="post" action="/custom-registers/{reg_slug}/columns/{column['id']}/delete" class="inline-form" onsubmit="return confirm('Энэ баганыг устгах уу? Холбогдох бүх утга бас устна.');">
                  <button type="submit" class="link-button danger">Устгах</button>
                </form>
              </td>
            </tr>
            """
        )
    manage_panel = f"""
      <div id="{manage_toggle_id}" class="toggle-form" hidden>
        <div class="manage-columns-panel">
          <form method="post" action="/custom-registers/{reg_slug}/columns/create" class="stack-form upload-form upload-form-panel compact-manage-form">
            <label>Баганын нэр<input type="text" name="name" placeholder="Жишээ: Хугацаа" required></label>
            <button type="submit">Багана нэмэх</button>
          </form>
          <div class="table-wrap nested-table-wrap">
            <table>
              <thead>
                <tr><th>Багана</th><th>Нэр өөрчлөх</th><th>Товч мэдээлэлд</th><th></th></tr>
              </thead>
              <tbody>{''.join(manage_rows) if manage_rows else '<tr><td colspan="4">Одоогоор багана алга.</td></tr>'}</tbody>
            </table>
          </div>
        </div>
      </div>
    """

    # Collapsible add-row form
    add_row_panel = ""
    if columns:
        fields = "".join(
            f'<label>{html.escape(col["name"])}<input type="text" name="column_{col["id"]}" placeholder="{html.escape(col["name"])}"></label>'
            for col in columns
        )
        add_row_panel = f"""
        <div id="{add_row_toggle_id}" class="toggle-form" hidden>
          <form method="post" action="/custom-registers/{reg_slug}/rows/new" class="stack-form upload-form upload-form-panel compact-manage-form">
            {fields}
            <button type="submit">Хадгалах</button>
          </form>
        </div>
        """

    # Cards for existing rows
    brief_cols_ordered = [col for col in columns if col["id"] in brief_col_ids]
    display_cols = brief_cols_ordered if brief_cols_ordered else columns[:3]
    cards = []
    search_data = []
    for index, entry in enumerate(reversed(row_entries), start=1):
        row = entry["row"]
        values = entry["values"]
        fields_html = "".join(
            f'<div class="reg-card-field">'
            f'<span class="reg-card-label">{html.escape(col["name"])}</span>'
            f'<span class="reg-card-value">{format_multiline(values.get(col["slug"], "—"))}</span>'
            f'</div>'
            for col in display_cols
        )
        cards.append(
            f"""
            <article class="card reg-card" data-row-id="{row['id']}" data-row-num="{index}">
              <div class="reg-card-index">#{index}</div>
              <div class="reg-card-fields">{fields_html}</div>
              <div class="reg-card-actions action-strip">
                <a class="button-link ghost small" href="/custom-registers/{reg_slug}/rows/{row['id']}">More</a>
                <a class="button-link ghost small" href="/custom-registers/{reg_slug}/rows/{row['id']}/edit">Засах</a>
                <form method="post" action="/custom-registers/{reg_slug}/rows/{row['id']}/delete" class="inline-form" onsubmit="return confirm('Энэ мөрийг устгах уу?');">
                  <button type="submit" class="link-button danger">Устгах</button>
                </form>
              </div>
            </article>
            """
        )
        cells = [
            {"col": col["name"], "val": values.get(col["slug"], "")}
            for col in columns
            if values.get(col["slug"], "").strip()
        ]
        search_data.append({"num": index, "id": row["id"], "cells": cells})

    search_data_json = json.dumps(search_data, ensure_ascii=False)
    search_widget = f"""
    <div class="reg-search-wrap" id="reg-search-wrap-{register['id']}">
      <input type="text" class="reg-search-input" placeholder="Хайх... (2+ тэмдэгт)"
             autocomplete="off"
             oninput="regSearch(this, {register['id']})"
             onkeydown="regSearchKey(event, {register['id']})"
             onblur="setTimeout(function(){{regSearchHide({register['id']})}}, 180)">
      <div class="reg-search-dropdown" id="reg-search-dd-{register['id']}" hidden></div>
    </div>
    <script>
    (function() {{
      var DATA_{register['id']} = {search_data_json};
      window._regSearchData = window._regSearchData || {{}};
      window._regSearchData[{register['id']}] = DATA_{register['id']};
    }})();
    </script>
    """ if columns else ""

    empty_msg = '<p class="muted">Одоогоор мөр алга.</p>' if not cards else ""
    add_row_btn = (
        f'<button type="button" class="button-link small" onclick="toggleVisibility(\'{add_row_toggle_id}\', this)"'
        f' data-open-label="Мөр нэмэх" data-close-label="Хаах" aria-expanded="false">Мөр нэмэх</button>'
        if columns else ""
    )
    body = f"""
    <section class="panel">
      <h1>{html.escape(register['title'])}</h1>
      <p class="muted">{html.escape(register['description'] or 'Тайлбар оруулаагүй байна.')}</p>
    </section>
    <section class="panel">
      <div class="heading-row compact-heading-row">
        <div>
          <h2>Жагсаалт</h2>
        </div>
        <div class="action-strip">
          {add_row_btn}
          <button type="button" class="button-link ghost manage-columns-button" onclick="toggleVisibility('{manage_toggle_id}', this)" data-open-label="Багана удирдах" data-close-label="Багана удирдах" aria-expanded="false">Багана удирдах</button>
        </div>
      </div>
      {add_row_panel}
      {manage_panel}
      {search_widget}
      <div class="card-grid reg-card-grid">{''.join(cards)}</div>
      {empty_msg}
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


def create_empty_docx(file_path):
    CONTENT_TYPES_XML = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )
    RELS_XML = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1"'
        ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
        ' Target="word/document.xml"/>'
        '</Relationships>'
    )
    DOC_XML = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p/></w:body></w:document>'
    )
    DOC_RELS_XML = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
    )
    with ZipFile(file_path, 'w', ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", CONTENT_TYPES_XML.encode("utf-8"))
        zf.writestr("_rels/.rels", RELS_XML.encode("utf-8"))
        zf.writestr("word/document.xml", DOC_XML.encode("utf-8"))
        zf.writestr("word/_rels/document.xml.rels", DOC_RELS_XML.encode("utf-8"))


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


def list_subfiles_for_doc(conn, parent_file_name):
    rows = conn.execute(
        "SELECT sf.*, u.username as uploader_name FROM admin_document_subfiles sf "
        "LEFT JOIN users u ON sf.uploaded_by = u.id "
        "WHERE sf.parent_file_name = ? ORDER BY sf.uploaded_at ASC",
        (parent_file_name,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_subfile(conn, subfile_id):
    row = conn.execute(
        "SELECT * FROM admin_document_subfiles WHERE id = ?", (subfile_id,)
    ).fetchone()
    return dict(row) if row else None


def _allowed_subfile_suffixes():
    return {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".zip"}


def _file_in_public_category(conn, file_name):
    row = conn.execute(
        "SELECT adc.slug FROM admin_document_category_links adcl "
        "JOIN admin_document_categories adc ON adcl.category_id = adc.id "
        "WHERE adcl.file_name = ?",
        (file_name,),
    ).fetchone()
    return row and row["slug"] in PUBLIC_DOC_CATEGORY_SLUGS


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
    cat_id = category["id"]
    file_item_parts = []
    for d in docs:
        subfiles = list_subfiles_for_doc(conn, d.name)
        sub_count = len(subfiles)
        sub_badge = f' <span class="muted" style="font-size:0.75rem">📎 {sub_count}</span>' if sub_count else ""
        subfile_rows_html = ""
        for sf in subfiles:
            dl_href = f"/admin-docs/{quote(d.name)}/subfiles/{sf['id']}/download"
            del_action = f"/admin-docs/{quote(d.name)}/subfiles/{sf['id']}/delete"
            date_label = html.escape((sf.get("uploaded_at") or "")[:10])
            uploader = html.escape(sf.get("uploader_name") or "")
            del_btn = ""
            if is_admin_or_above(user):
                del_btn = f'<form method="post" action="{del_action}" class="inline-form" onsubmit="return confirm(\'Дэд файлыг устгах уу?\')"><button type="submit" class="link-button danger" style="font-size:0.75rem">Устгах</button></form>'
            view_href = f"/admin-docs/{quote(d.name)}/subfiles/{sf['id']}/view"
            subfile_rows_html += f"""<tr>
              <td><a class="table-link" href="{view_href}" style="font-size:0.8125rem">📎 {html.escape(sf['original_name'])}</a></td>
              <td class="muted" style="font-size:0.75rem">{date_label}</td>
              <td class="muted" style="font-size:0.75rem">{uploader}</td>
              <td class="table-actions"><div class="action-strip">
                <a class="button-link small" href="{view_href}">Харах</a>
                <a class="button-link ghost small" href="{dl_href}">Татах</a>
                {del_btn}
              </div></td>
            </tr>"""
        subfiles_block = ""
        if subfiles:
            subfiles_block = f"""<div class="table-wrap" style="margin-top:8px;margin-left:2px">
              <table style="font-size:0.8125rem">
                <thead><tr><th>Дэд файл</th><th>Огноо</th><th>Оруулсан</th><th></th></tr></thead>
                <tbody>{subfile_rows_html}</tbody>
              </table>
            </div>"""
        upload_form_html = ""
        if is_admin_or_above(user):
            upload_form_html = (
                f'<details style="margin-top:6px">'
                f'<summary style="cursor:pointer;font-size:0.8rem;font-weight:600;color:var(--primary);list-style:none;display:inline-flex;align-items:center;gap:4px">'
                f'<span style="font-size:0.65rem">&#9658;</span> Дэд файл нэмэх</summary>'
                f'<form method="post" action="/admin-docs/{quote(d.name)}/subfiles/upload"'
                f' enctype="multipart/form-data"'
                f' style="margin-top:6px;padding:10px 12px;background:var(--surface-alt);border:1px solid var(--border);border-radius:var(--radius-md);display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
                f'<input type="file" name="subfile" accept=".pdf,.doc,.docx,.xls,.xlsx,.png,.jpg,.jpeg,.txt,.csv,.zip" required style="font-size:0.8rem">'
                f'<button type="submit" class="ghost small">Нэмэх</button></form></details>'
            )
        _incident_btn = (
            '<a class="button-link ghost small" href="/admin-docs/registers/zorchlin-burtgel/new">Зөрчил нэмэх</a>'
            if "L1-POL-12" in d.name and is_admin_or_above(user) else ""
        )
        _mgmt_btns = (
            f'<details style="display:inline-block">'
            f'<summary style="cursor:pointer;list-style:none">'
            f'<span class="button-link ghost small" style="pointer-events:none">Шинэчлэх &#9660;</span></summary>'
            f'<form method="post" action="/admin-docs/{quote(d.name)}/replace" enctype="multipart/form-data" class="admin-doc-replace-form">'
            f'<input type="hidden" name="return_to" value="/admin-doc-categories/{cat_id}">'
            f'<input type="file" name="document" required style="font-size:0.75rem">'
            f'<button type="submit" class="ghost small">Оруулах</button></form></details>'
            f'<form method="post" action="/admin-docs/{quote(d.name)}/delete" class="inline-form"'
            f' onsubmit="return confirm(\'Энэ файлыг устгах уу?\')">'
            f'<input type="hidden" name="return_to" value="/admin-doc-categories/{cat_id}">'
            f'<button type="submit" class="link-button danger">Устгах</button></form>'
        ) if is_admin_or_above(user) else ""
        file_item_parts.append(f"""<div class="admin-doc-file-item" style="flex-direction:column;align-items:stretch">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px">
            <div class="admin-doc-file-name">
              <a class="table-link" href="/admin-docs/{quote(d.name)}">{html.escape(d.name)}</a>
              <span class="admin-doc-file-ext">{html.escape(d.suffix.lstrip('.') or 'file').upper()}</span>
              {sub_badge}
            </div>
            <div class="admin-doc-file-actions">
              <a class="button-link small" href="/admin-docs/{quote(d.name)}">Нээх</a>
              <a class="button-link ghost small" href="/admin-docs/{quote(d.name)}/download">Татах</a>
              {_incident_btn}
              {_mgmt_btns}
            </div>
          </div>
          {subfiles_block}
          {upload_form_html}
        </div>""")
    file_items = "".join(file_item_parts)
    empty = '<p class="muted" style="font-style:italic;padding:8px 0">Одоогоор файл алга.</p>'
    back_href = "/admin-docs" if is_admin_or_above(user) else "/dashboard"
    add_file_section = ""
    if is_admin_or_above(user):
        add_file_section = f"""<details style="margin-top:16px">
      <summary style="cursor:pointer;font-size:0.8125rem;font-weight:600;color:var(--primary);list-style:none;display:inline-flex;align-items:center;gap:5px">
        <span style="font-size:0.7rem">▸</span> Файл нэмэх
      </summary>
      <form method="post" action="/admin-docs/create" enctype="multipart/form-data" class="stack-form" style="margin-top:8px;padding:12px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-md)">
        <input type="hidden" name="category_id" value="{cat_id}">
        <input type="hidden" name="return_to" value="/admin-doc-categories/{cat_id}">
        <label>Файлын нэр<input type="text" name="filename" placeholder="example.pdf" required></label>
        <label>Файл (заавал биш)<input type="file" name="document"></label>
        <button type="submit">Нэмэх</button>
      </form>
    </details>"""
    body = f"""
    <div class="heading-row compact-heading-row" style="margin-bottom:20px">
      <h1>{html.escape(category['name'])}</h1>
      <a class="button-link ghost" href="{back_href}">← Буцах</a>
    </div>
    <div class="admin-doc-file-list">
      {file_items if file_items else empty}
    </div>
    {add_file_section}
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
    category_panels = []
    for category in categories:
        docs = list_documents_for_admin_category(conn, category["id"])
        file_row_parts = []
        for d in docs:
            sub_count = conn.execute(
                "SELECT COUNT(*) FROM admin_document_subfiles WHERE parent_file_name = ?", (d.name,)
            ).fetchone()[0]
            sub_badge = f' <span title="Дэд файл" style="font-size:0.7rem;color:var(--muted)">📎{sub_count}</span>' if sub_count else ""
            file_row_parts.append(f"""<tr>
              <td style="padding-left:20px">
                <a class="table-link" href="/admin-docs/{quote(d.name)}">{html.escape(d.name)}</a>{sub_badge}
              </td>
              <td class="muted">{html.escape(d.suffix.lstrip('.') or 'file').upper()}</td>
              <td class="table-actions">
                <div class="action-strip">
                  <a class="button-link small" href="/admin-docs/{quote(d.name)}">Нээх</a>
                  <a class="button-link ghost small" href="/admin-docs/{quote(d.name)}/download">Татах</a>
                  <form method="post" action="/admin-docs/{quote(d.name)}/replace" enctype="multipart/form-data" style="display:inline-flex;align-items:center;gap:4px">
                    <input type="hidden" name="return_to" value="/admin-docs">
                    <input type="file" name="document" required style="font-size:0.75rem;max-width:150px">
                    <button type="submit" class="ghost small">Шинэчлэх</button>
                  </form>
                  <form method="post" action="/admin-docs/{quote(d.name)}/delete" class="inline-form" onsubmit="return confirm('Энэ файлыг устгах уу?');">
                    <input type="hidden" name="return_to" value="/admin-docs">
                    <button type="submit" class="link-button danger">Устгах</button>
                  </form>
                </div>
              </td>
            </tr>""")
        file_rows = "".join(file_row_parts)
        empty_row = '<tr><td colspan="3" class="muted" style="padding-left:20px;font-style:italic">Одоогоор файл алга.</td></tr>'
        cat_id = category["id"]
        category_panels.append(f"""
        <div class="admin-doc-category-block">
          <div class="admin-doc-category-header">
            <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0">
              <span class="admin-doc-category-title">{html.escape(category['name'])}</span>
              <span class="doc-count" style="font-size:0.75rem;color:var(--muted)">{len(docs)} файл</span>
            </div>
            <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
              <form method="post" action="/admin-doc-categories/{cat_id}/rename" class="inline-rename-form" style="display:inline-flex;align-items:center;gap:4px">
                <input type="text" name="name" value="{html.escape(category['name'])}" class="table-inline-input compact-input" required style="font-size:0.75rem;height:26px;padding:0 7px">
                <button type="submit" class="ghost small">Нэр өөрчлөх</button>
              </form>
              <form method="post" action="/admin-doc-categories/{cat_id}/delete" class="inline-form" onsubmit="return confirm('Энэ ангиллыг устгах уу?');">
                <button type="submit" class="link-button danger" style="font-size:0.75rem">Устгах</button>
              </form>
            </div>
          </div>
          <div class="admin-doc-category-body">
            <div class="table-wrap">
              <table>
                <thead><tr><th style="padding-left:20px">Файлын нэр</th><th>Төрөл</th><th></th></tr></thead>
                <tbody>{file_rows if file_rows else empty_row}</tbody>
              </table>
            </div>
            <details style="margin-top:10px">
              <summary style="cursor:pointer;font-size:0.8125rem;font-weight:600;color:var(--primary);padding:4px 6px;list-style:none;display:inline-flex;align-items:center;gap:5px">
                <span style="font-size:0.7rem">▸</span> Файл нэмэх
              </summary>
              <form method="post" action="/admin-docs/create" enctype="multipart/form-data" class="stack-form" style="margin-top:8px;padding:12px 14px;background:var(--surface-alt);border:1px solid var(--border);border-radius:var(--radius-md);margin-left:12px">
                <input type="hidden" name="category_id" value="{cat_id}">
                <input type="hidden" name="return_to" value="/admin-docs">
                <label>Файлын нэр<input type="text" name="filename" placeholder="example.pdf" required></label>
                <label>Файл (заавал биш)<input type="file" name="document"></label>
                <button type="submit">Нэмэх</button>
              </form>
            </details>
          </div>
        </div>""")

    panels_html = "\n".join(category_panels) if category_panels else '<p class="muted">Одоогоор ангилал алга.</p>'
    return f"""
    <div class="heading-row compact-heading-row" style="margin-bottom:20px">
      <h1>Админ баримтууд</h1>
      <details>
        <summary style="cursor:pointer;font-size:0.8125rem;font-weight:600;color:var(--primary);list-style:none;display:inline-flex;align-items:center;gap:5px">
          <span style="font-size:0.7rem">▸</span> Шинэ ангилал нэмэх
        </summary>
        <form method="post" action="/admin-doc-categories/create" class="stack-form" style="margin-top:8px;padding:12px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-md)">
          <label>Ангиллын нэр<input type="text" name="name" placeholder="Жишээ: Ажиллах заавар" required></label>
          <button type="submit">Ангилал нэмэх</button>
        </form>
      </details>
    </div>
    <div class="admin-doc-overview">
      {panels_html}
    </div>
    """


def render_admin_docs_manage_page(conn, user, notice=""):
    categories = list_admin_document_categories(conn)
    sections = []
    for cat in categories:
        docs = list_documents_for_admin_category(conn, cat["id"])
        doc_rows = "".join(
            f"""<tr>
              <td>{html.escape(d.name)}</td>
              <td class="table-actions"><div class="action-strip">
                <a class="button-link ghost small" href="/admin-docs/{quote(d.name)}">Нээх</a>
                <form method="post" action="/admin-docs/{quote(d.name)}/delete" class="inline-form"
                      onsubmit="return confirm('{html.escape(d.name)} устгах уу?')">
                  <input type="hidden" name="return_to" value="/admin-docs/manage">
                  <button class="link-button danger" type="submit">Устгах</button>
                </form>
              </div></td>
            </tr>"""
            for d in docs
        )
        sections.append(f"""
        <section class="panel">
          <div class="heading-row compact-heading-row">
            <div>
              <h2>{html.escape(cat['name'])}</h2>
              <p class="muted">{len(docs)} файл</p>
            </div>
            <div class="action-strip">
              <form method="post" action="/admin-doc-categories/{cat['id']}/rename" class="inline-rename-form">
                <input type="text" name="name" value="{html.escape(cat['name'])}" class="table-inline-input compact-input" required>
                <button type="submit" class="button-link ghost small">Нэр өөрчлөх</button>
              </form>
              <form method="post" action="/admin-doc-categories/{cat['id']}/delete" class="inline-form"
                    onsubmit="return confirm('{html.escape(cat['name'])} ангиллыг устгах уу?')">
                <button type="submit" class="link-button danger">Ангилал устгах</button>
              </form>
            </div>
          </div>
          <form method="post" action="/admin-docs/create" enctype="multipart/form-data" class="stack-form upload-form" style="margin-bottom:12px">
            <input type="hidden" name="category_id" value="{cat['id']}">
            <input type="hidden" name="return_to" value="/admin-docs/manage">
            <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
              <label style="flex:1;min-width:160px">Файлын нэр<input type="text" name="filename" placeholder="example.pdf" required></label>
              <label>Файл (заавал биш)<input type="file" name="document"></label>
              <button type="submit">Нэмэх</button>
            </div>
          </form>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Файл</th><th></th></tr></thead>
              <tbody>{doc_rows if doc_rows else '<tr><td colspan="2" class="muted">Файл алга.</td></tr>'}</tbody>
            </table>
          </div>
        </section>
        """)
    new_cat_form = f"""
    <section class="panel">
      <h2>Шинэ ангилал нэмэх</h2>
      <form method="post" action="/admin-doc-categories/create" class="stack-form" style="max-width:400px">
        <label>Ангиллын нэр<input type="text" name="name" placeholder="Жишээ: Ажиллах заавар" required autofocus></label>
        <button type="submit">Ангилал нэмэх</button>
      </form>
    </section>
    """
    body = new_cat_form + "".join(sections)
    return render_page("Админ баримтууд — Засах", user, body, notice)


def _filter_incident_section(blocks):
    filtered = []
    skip_next_table = False
    for block_type, value in blocks:
        if block_type == "paragraph" and "Хавсралт 4" in value:
            skip_next_table = True
            continue
        if block_type == "table" and skip_next_table:
            skip_next_table = False
            continue
        skip_next_table = False
        filtered.append((block_type, value))
    return filtered


def attachment_register_export_matrix(conn, register):
    export_fields = [
        (fn, label, ft)
        for fn, label, _, ft in register["fields"]
    ]
    headers = ["№"] + [label for _, label, _ in export_fields]
    rows = conn.execute(f"SELECT * FROM {register['table']} ORDER BY id ASC").fetchall()
    matrix = [headers]
    for row in rows:
        cells = [str(row["id"])]
        for field_name, _, field_type in export_fields:
            if field_type == "computed":
                cells.append(resolve_computed_field(field_name, row) or "")
            else:
                cells.append(row[field_name] or "")
        matrix.append(cells)
    return matrix


def admin_document_view_page(conn, user, file_path, notice=""):
    category = assigned_admin_document_category(conn, file_path.name)
    back_href = f"/admin-doc-categories/{category['id']}" if category else "/dashboard"
    is_incident_doc = "L1-POL-12" in file_path.name
    file_suffix = file_path.suffix.lower()
    if file_suffix == ".pdf":
        embed_href = f"/admin-docs/{quote(file_path.name)}/embed"
        content = f'<iframe src="{embed_href}" class="pdf-frame" title="{html.escape(file_path.name)}"></iframe>'
    else:
        blocks = extract_docx_blocks(file_path)
        if is_incident_doc:
            blocks = _filter_incident_section(blocks)
        content = render_docx_blocks_html(blocks)
    download_href = f"/admin-docs/{quote(file_path.name)}/download"
    incident_register = get_attachment_register("zorchlin-burtgel")
    incident_buttons = ""
    if is_incident_doc and incident_register:
        incident_buttons = f"""
          <a class="button-link ghost" href="/admin-docs/registers/zorchlin-burtgel">Зөрчлийн бүртгэл</a>
          <a class="button-link ghost" href="/admin-docs/registers/zorchlin-burtgel/export.xlsx">Татах (Excel)</a>"""
    update_section = ""
    if is_superadmin(user):
        update_section = f"""
    <section class="panel">
      <h2>Файл шинэчлэх</h2>
      <p class="muted">Шинэ файл сонгоно уу. Баталгаажуулахаас өмнө урьдчилан харагдацыг шалгана.</p>
      <form method="post" action="/admin-docs/{quote(file_path.name)}/preview"
            enctype="multipart/form-data" class="stack-form" style="max-width:480px">
        <div class="drop-zone" id="doc-drop-zone">
          <p class="drop-zone-label" id="drop-zone-label">Файл чирж оруулах эсвэл дарна уу<br>
            <span class="muted" style="font-size:0.8125rem">.docx, .pdf, .doc, .xls, .xlsx</span>
          </p>
          <input type="file" name="document" accept=".docx,.pdf,.doc,.xls,.xlsx"
                 id="doc-file-input" class="drop-zone-input" required>
        </div>
        <button type="submit">Урьдчилан харах →</button>
      </form>
      <script>
      (function(){{
        var zone=document.getElementById('doc-drop-zone');
        var input=document.getElementById('doc-file-input');
        var label=document.getElementById('drop-zone-label');
        zone.addEventListener('dragover',function(e){{e.preventDefault();zone.classList.add('drop-zone-active');}});
        zone.addEventListener('dragleave',function(){{zone.classList.remove('drop-zone-active');}});
        zone.addEventListener('drop',function(e){{
          e.preventDefault();zone.classList.remove('drop-zone-active');
          var files=e.dataTransfer.files;
          if(files.length>0){{
            try{{var dt=new DataTransfer();dt.items.add(files[0]);input.files=dt.files;}}catch(err){{}}
            label.innerHTML=files[0].name;
          }}
        }});
        input.addEventListener('change',function(){{
          if(input.files.length>0)label.innerHTML=input.files[0].name;
        }});
      }})();
      </script>
    </section>"""
    subfiles = list_subfiles_for_doc(conn, file_path.name)
    subfile_rows = ""
    for sf in subfiles:
        view_href = f"/admin-docs/{quote(file_path.name)}/subfiles/{sf['id']}/view"
        dl_href = f"/admin-docs/{quote(file_path.name)}/subfiles/{sf['id']}/download"
        del_action = f"/admin-docs/{quote(file_path.name)}/subfiles/{sf['id']}/delete"
        uploaded_label = html.escape(sf.get("uploader_name") or "")
        date_label = html.escape((sf.get("uploaded_at") or "")[:10])
        delete_btn = ""
        if is_admin_or_above(user):
            delete_btn = f"""<form method="post" action="{del_action}" class="inline-form" onsubmit="return confirm('Дэд файлыг устгах уу?')">
                <button type="submit" class="link-button danger">Устгах</button>
              </form>"""
        subfile_rows += f"""<tr>
          <td><a class="table-link" href="{view_href}">📎 {html.escape(sf['original_name'])}</a></td>
          <td class="muted">{date_label}</td>
          <td class="muted">{uploaded_label}</td>
          <td class="table-actions">
            <div class="action-strip">
              <a class="button-link small" href="{view_href}">Харах</a>
              <a class="button-link ghost small" href="{dl_href}">Татах</a>
              {delete_btn}
            </div>
          </td>
        </tr>"""
    subfiles_table = ""
    if subfiles:
        subfiles_table = f"""<div class="table-wrap" style="margin-bottom:12px">
          <table>
            <thead><tr><th>Файлын нэр</th><th>Огноо</th><th>Оруулсан</th><th></th></tr></thead>
            <tbody>{subfile_rows}</tbody>
          </table>
        </div>"""
    else:
        subfiles_table = '<p class="muted" style="margin-bottom:12px">Одоогоор дэд файл алга.</p>'
    upload_form = ""
    if is_admin_or_above(user):
        upload_form = f"""<details style="margin-top:8px">
          <summary style="cursor:pointer;font-size:0.8125rem;font-weight:600;color:var(--primary);list-style:none;display:inline-flex;align-items:center;gap:5px">
            <span style="font-size:0.7rem">▸</span> Дэд файл нэмэх
          </summary>
          <form method="post" action="/admin-docs/{quote(file_path.name)}/subfiles/upload"
                enctype="multipart/form-data" class="stack-form"
                style="margin-top:8px;padding:12px 14px;background:var(--surface-alt);border:1px solid var(--border);border-radius:var(--radius-md)">
            <label>Файл сонгох
              <input type="file" name="subfile" accept=".pdf,.doc,.docx,.xls,.xlsx,.png,.jpg,.jpeg,.txt,.csv,.zip" required>
            </label>
            <button type="submit">Нэмэх</button>
          </form>
        </details>"""
    subfiles_section = f"""
    <section class="panel">
      <h2>Дэд файлууд <span class="muted" style="font-size:0.85rem;font-weight:400">({len(subfiles)})</span></h2>
      {subfiles_table}
      {upload_form}
    </section>"""
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(file_path.name)}</h1>
          <p class="muted">Админ хэрэглэгчид зориулсан баримтын харагдац.</p>
        </div>
        <div class="action-strip">
          <a class="button-link ghost" href="{back_href}">Буцах</a>{incident_buttons}
          <a class="button-link" href="{download_href}">Татах</a>
        </div>
      </div>
      <section class="doc-viewer">{content}</section>
    </section>
    {subfiles_section}
    {update_section}
    """
    return render_page(file_path.name, user, body, notice)


def render_docx_blocks_html(blocks):
    rendered = []
    for block_type, value in blocks:
        if block_type == "paragraph":
            rendered.append(f"<p>{html.escape(value)}</p>")
        elif block_type == "table":
            row_html = []
            for row_index, row in enumerate(value):
                tag = "th" if row_index == 0 else "td"
                cells = "".join(f"<{tag}>{format_multiline(cell)}</{tag}>" for cell in row)
                row_html.append(f"<tr>{cells}</tr>")
            rendered.append(f'<div class="doc-table-wrap"><table class="doc-table">{"".join(row_html)}</table></div>')
    return "".join(rendered) or "<p class=\"muted\">Агуулга уншиж чадсангүй.</p>"


def render_docx_blocks_editable_html(blocks):
    rendered = []
    for bi, (block_type, value) in enumerate(blocks):
        if block_type == "paragraph":
            rendered.append(
                f'<p contenteditable="true" data-bi="{bi}" data-btype="paragraph"'
                f' class="editable-block">{html.escape(value)}</p>'
            )
        elif block_type == "table":
            row_html = []
            for ri, row in enumerate(value):
                tag = "th" if ri == 0 else "td"
                cells = "".join(
                    f'<{tag} contenteditable="true" data-bi="{bi}" data-btype="table"'
                    f' data-ri="{ri}" data-ci="{ci}" class="editable-cell">{html.escape(cell)}</{tag}>'
                    for ci, cell in enumerate(row)
                )
                row_html.append(f"<tr>{cells}</tr>")
            rendered.append(
                f'<div class="doc-table-wrap"><table class="doc-table">{"".join(row_html)}</table></div>'
            )
    return "".join(rendered) or "<p class=\"muted\">Агуулга уншиж чадсангүй.</p>"


def apply_docx_edits(tmp_path, edits_json):
    import re as _re
    try:
        edits = json.loads(edits_json)
        if not edits:
            return True
    except Exception:
        return False

    W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
    try:
        with ZipFile(tmp_path) as zin:
            xml_bytes = zin.read("word/document.xml")
            file_map = {n: zin.read(n) for n in zin.namelist() if n != "word/document.xml"}
    except Exception:
        return False

    for prefix_b, uri_b in _re.findall(rb'xmlns:([A-Za-z0-9_]+)="([^"]+)"', xml_bytes):
        try:
            ET.register_namespace(prefix_b.decode(), uri_b.decode())
        except Exception:
            pass

    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return False

    body = root.find(f'{{{W}}}body')
    if body is None:
        return False

    blocks = []
    for child in list(body):
        tag = child.tag.rsplit('}', 1)[-1]
        if tag == 'p':
            if docx_text_from_node(child):
                blocks.append(('p', child))
        elif tag == 'tbl':
            has_content = any(
                docx_text_from_node(cell)
                for row in child.findall(f'{{{W}}}tr')
                for cell in row.findall(f'{{{W}}}tc')
            )
            if has_content:
                blocks.append(('tbl', child))

    for edit in edits:
        bi = edit.get('bi')
        if not isinstance(bi, int) or bi >= len(blocks):
            continue
        blk_tag, elem = blocks[bi]
        new_text = str(edit.get('text', ''))

        if edit.get('type') == 'paragraph' and blk_tag == 'p':
            t_nodes = elem.findall(f'.//{{{W}}}t')
            if t_nodes:
                t_nodes[0].text = new_text
                for t in t_nodes[1:]:
                    t.text = ''

        elif edit.get('type') == 'table' and blk_tag == 'tbl':
            ri, ci = edit.get('ri', 0), edit.get('ci', 0)
            rows = elem.findall(f'{{{W}}}tr')
            if isinstance(ri, int) and ri < len(rows):
                cells = rows[ri].findall(f'{{{W}}}tc')
                if isinstance(ci, int) and ci < len(cells):
                    t_nodes = cells[ci].findall(f'.//{{{W}}}t')
                    if t_nodes:
                        t_nodes[0].text = new_text
                        for t in t_nodes[1:]:
                            t.text = ''

    try:
        new_xml = ET.tostring(root, encoding='unicode')
        if not new_xml.startswith('<?xml'):
            new_xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + new_xml
        tmp_out = tmp_path.parent / (tmp_path.name + '.editmp')
        with ZipFile(tmp_out, 'w', ZIP_DEFLATED) as zout:
            for name, data in file_map.items():
                zout.writestr(name, data)
            zout.writestr("word/document.xml", new_xml.encode('utf-8'))
        tmp_out.replace(tmp_path)
        return True
    except Exception:
        return False


def admin_document_preview_page(conn, user, original_path, tmp_path, token):
    suffix = tmp_path.suffix.lower()
    is_docx = suffix == ".docx"
    is_pdf = suffix == ".pdf"
    if is_docx:
        blocks = extract_docx_blocks(tmp_path)
        preview_html = render_docx_blocks_editable_html(blocks)
        preview_section = f'<section class="doc-viewer">{preview_html}</section>'
        edit_note = '<p class="muted" style="margin-bottom:8px">Текстэн дээр дарж засварлах боломжтой.</p>'
    elif is_pdf:
        preview_section = f'<iframe src="/admin-docs/preview-file/{token}" class="pdf-frame" title="{html.escape(original_path.name)}"></iframe>'
        edit_note = ""
    else:
        preview_section = f'<p class="muted">Энэ файлын төрөлд ({html.escape(suffix)}) урьдчилан харагдах боломжгүй. Доорх товчоор баталгаажуулж шинэчилнэ үү.</p>'
        edit_note = ""
    back_href = f"/admin-docs/{quote(original_path.name)}"
    collect_js = """
<script>
function collectEdits() {
  var edits = [];
  document.querySelectorAll('[data-btype="paragraph"]').forEach(function(el) {
    edits.push({type:'paragraph', bi:+el.dataset.bi, text:(el.innerText||el.textContent||'').trim()});
  });
  document.querySelectorAll('[data-btype="table"]').forEach(function(el) {
    edits.push({type:'table', bi:+el.dataset.bi, ri:+el.dataset.ri, ci:+el.dataset.ci, text:(el.innerText||el.textContent||'').trim()});
  });
  return JSON.stringify(edits);
}
</script>""" if is_docx else ""
    edits_input = '<input type="hidden" name="edits" id="edits-input" value="">' if is_docx else ""
    onsubmit = ' onsubmit="document.getElementById(\'edits-input\').value=collectEdits()"' if is_docx else ""
    body = f"""
    {collect_js}
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(original_path.name)}</h1>
          <p class="muted">Шинэ файлын урьдчилан харагдац. Зөв эсэхийг шалгаад баталгаажуулна уу.</p>
        </div>
        <a class="button-link ghost" href="{back_href}">Болих</a>
      </div>
    </section>
    <section class="panel">
      <div class="heading-row compact-heading-row">
        <h2>Шинэ агуулга</h2>
        <form method="post" action="/admin-docs/{quote(original_path.name)}/confirm-replace"{onsubmit}>
          {edits_input}
          <input type="hidden" name="preview_token" value="{html.escape(token)}">
          <button type="submit" class="button-link">Баталгаажуулж шинэчлэх</button>
        </form>
      </div>
      {edit_note}
      {preview_section}
    </section>
    """
    return render_page(f"Урьдчилан харах — {original_path.name}", user, body)


def send_file(start_response, file_path, download_name=None):
    guessed_type, _ = mimetypes.guess_type(str(file_path))
    content_type = guessed_type or "application/octet-stream"
    payload = file_path.read_bytes()
    dl_name = download_name or file_path.name
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(payload))),
        ("Content-Disposition", f"attachment; filename*=UTF-8''{quote(dl_name)}"),
    ]
    start_response("200 OK", headers)
    return [payload]


def send_inline_file(start_response, file_path, download_name=None):
    guessed_type, _ = mimetypes.guess_type(str(file_path))
    content_type = guessed_type or "application/octet-stream"
    payload = file_path.read_bytes()
    dl_name = download_name or file_path.name
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(payload))),
        ("Content-Disposition", f"inline; filename*=UTF-8''{quote(dl_name)}"),
    ]
    start_response("200 OK", headers)
    return [payload]


def _render_xlsx_as_html(file_path):
    try:
        wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
        parts = []
        for sheet in wb.worksheets:
            rows_html = ""
            for ri, row in enumerate(sheet.iter_rows(values_only=True)):
                if all(c is None for c in row):
                    continue
                tag = "th" if ri == 0 else "td"
                cells = "".join(f"<{tag}>{html.escape(str(c) if c is not None else '')}</{tag}>" for c in row)
                rows_html += f"<tr>{cells}</tr>"
            if rows_html:
                parts.append(
                    f'<p style="font-weight:600;margin:12px 0 4px">{html.escape(sheet.title)}</p>'
                    f'<div class="doc-table-wrap"><table class="doc-table">{rows_html}</table></div>'
                )
        wb.close()
        return "".join(parts) or "<p class='muted'>Хоосон файл.</p>"
    except Exception as e:
        return f"<p class='muted'>Excel файл уншиж чадсангүй: {html.escape(str(e))}</p>"


def admin_subfile_view_page(conn, user, parent_file, sf):
    raw_href = f"/admin-docs/{quote(parent_file.name)}/subfiles/{sf['id']}/raw"
    dl_href = f"/admin-docs/{quote(parent_file.name)}/subfiles/{sf['id']}/download"
    back_href = f"/admin-docs/{quote(parent_file.name)}"
    suffix = Path(sf["original_name"]).suffix.lower()
    stored_path = SUBFILES_DIR / sf["stored_name"]
    if suffix == ".pdf":
        viewer = f'<iframe src="{raw_href}" class="pdf-frame" title="{html.escape(sf["original_name"])}"></iframe>'
    elif suffix in (".png", ".jpg", ".jpeg"):
        viewer = f'<img src="{raw_href}" alt="{html.escape(sf["original_name"])}" style="max-width:100%;border-radius:var(--radius-md);border:1px solid var(--border)">'
    elif suffix in (".docx", ".doc"):
        blocks = extract_docx_blocks(stored_path)
        viewer = render_docx_blocks_html(blocks)
    elif suffix in (".xlsx", ".xls"):
        viewer = _render_xlsx_as_html(stored_path)
    elif suffix in (".txt", ".csv"):
        try:
            text = stored_path.read_text(encoding="utf-8", errors="replace")
            viewer = f'<pre style="white-space:pre-wrap;word-break:break-word;font-size:0.8125rem;line-height:1.6">{html.escape(text)}</pre>'
        except Exception:
            viewer = f'<p class="muted">Файл уншиж чадсангүй.</p>'
    else:
        viewer = (
            f'<p class="muted">Энэ файлын төрлийг вэб дээр харах боломжгүй.</p>'
            f'<a href="{dl_href}" class="button-link" style="margin-top:12px;display:inline-flex">Татах</a>'
        )
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(sf["original_name"])}</h1>
          <p class="muted"><a href="{back_href}">{html.escape(parent_file.name)}</a> файлын дэд файл</p>
        </div>
        <div class="action-strip">
          <a class="button-link ghost" href="{back_href}">Буцах</a>
          <a class="button-link" href="{dl_href}">Татах</a>
        </div>
      </div>
      <section class="doc-viewer">{viewer}</section>
    </section>"""
    return render_page(sf["original_name"], user, body)


def docs_wall_html(user, conn):
    if not is_admin_or_above(user):
        return ""
    role = user_role(user)
    try:
        cats = conn.execute(
            "SELECT id, name FROM admin_document_categories ORDER BY display_order, name"
        ).fetchall()
        cat_sections = []
        for c in cats:
            docs = conn.execute(
                "SELECT adcl.file_name FROM admin_document_category_links adcl "
                "WHERE adcl.category_id = ? ORDER BY adcl.file_name",
                (c["id"],),
            ).fetchall()
            file_links = ""
            for d in docs:
                sub_count = conn.execute(
                    "SELECT COUNT(*) FROM admin_document_subfiles WHERE parent_file_name = ?",
                    (d["file_name"],),
                ).fetchone()[0]
                badge = f' <span class="docs-wall-badge">{sub_count}</span>' if sub_count else ""
                file_links += (
                    f'<a class="docs-wall-file" href="/admin-docs/{quote(d["file_name"])}">'
                    f'{html.escape(d["file_name"])}{badge}</a>'
                )
            if not file_links:
                file_links = '<span class="docs-wall-empty">Файл алга</span>'
            cat_sections.append(
                f'<div class="docs-wall-cat">'
                f'<a class="docs-wall-cat-name" href="/admin-doc-categories/{c["id"]}">'
                f'<span class="docs-wall-folder">📁</span>{html.escape(c["name"])}</a>'
                f'<div class="docs-wall-files">{file_links}</div>'
                f'</div>'
            )
        manage = ""
        if is_superadmin(user):
            manage = '<a class="docs-wall-manage" href="/admin-docs">⚙ Засах / удирдах</a>'
        body_content = "".join(cat_sections) + manage
        return f"""
  <div class="docs-wall" id="docs-wall">
    <div class="docs-wall-panel">
      <div class="docs-wall-header">Админ баримтууд</div>
      <div class="docs-wall-body">{body_content}</div>
    </div>
    <div class="docs-wall-tab"><span>Админ баримтууд</span></div>
  </div>"""
    except Exception:
        return ""


_AUDIT_ACTION_LABELS = {
    "login": ("Нэвтэрсэн", "login"),
    "logout": ("Гарсан", "login"),
    "login_failed": ("Нэвтрэх амжилтгүй", "danger"),
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
    "attachment_incident": "Зөрчлийн бүртгэл",
}


def audit_page(conn, user, notice="", query=None):
    query = query or {}
    users_for_suggest = conn.execute(
        "SELECT email, display_name, username FROM users WHERE is_active = 1 ORDER BY display_name, username"
    ).fetchall()
    users_json = json.dumps(
        [{"label": u["display_name"] or u["username"], "val": u["email"] or u["username"]}
         for u in users_for_suggest],
        ensure_ascii=False
    )
    # Discover all monthly audit tables
    raw_tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'audit_logs_____%' ORDER BY name DESC"
    ).fetchall()
    available_months = []
    for t in raw_tables:
        name = t["name"]
        if name.startswith("audit_logs_") and len(name) == len("audit_logs_YYYY_MM"):
            try:
                tail = name[len("audit_logs_"):]
                yr_s, mo_s = tail.split("_")
                available_months.append((int(yr_s), int(mo_s), name))
            except (ValueError, AttributeError):
                pass

    now_d = now_utc()
    search_q = (qs_value(query, "q") or "").strip()

    # Separate year and month params
    try:
        sel_year = int(qs_value(query, "year") or now_d.year)
    except (ValueError, TypeError):
        sel_year = now_d.year
    try:
        sel_month = int(qs_value(query, "month") or now_d.month)
    except (ValueError, TypeError):
        sel_month = now_d.month

    table = f"audit_logs_{sel_year}_{sel_month:02d}"
    table_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()

    rows = []
    like = f"%{search_q}%" if search_q else None

    def _build_query(tbl, like):
        if like:
            where = f"""WHERE (
                actor.username LIKE ? OR actor.email LIKE ? OR actor.display_name LIKE ?
                OR departments.name LIKE ?
                OR {tbl}.details LIKE ?
                OR {tbl}.created_at LIKE ?
            )"""
            params = [like, like, like, like, like, like]
        else:
            where, params = "", []
        sql = f"""
            SELECT {tbl}.*,
                   actor.username AS actor_username, actor.display_name AS actor_display_name,
                   target.username AS target_username, target.display_name AS target_display_name,
                   departments.name AS department_name
            FROM {tbl}
            LEFT JOIN users AS actor ON actor.id = {tbl}.actor_user_id
            LEFT JOIN users AS target ON target.id = {tbl}.target_user_id
            LEFT JOIN departments ON departments.id = {tbl}.department_id
            {where}
            ORDER BY {tbl}.created_at DESC, {tbl}.id DESC
        """
        return sql, params

    if like and available_months:
        for _, _, tbl_name in available_months:
            sql, params = _build_query(tbl_name, like)
            rows.extend(conn.execute(sql, params).fetchall())
    elif table_exists:
        sql, params = _build_query(table, None)
        rows = conn.execute(sql, params).fetchall()

    _AUDIT_PAGE_SIZE = 50
    total_count = len(rows)
    try:
        page_num = max(1, int(qs_value(query, "page") or 1))
    except (ValueError, TypeError):
        page_num = 1
    total_pages = max(1, (total_count + _AUDIT_PAGE_SIZE - 1) // _AUDIT_PAGE_SIZE)
    page_num = min(page_num, total_pages)
    page_rows = rows[(page_num - 1) * _AUDIT_PAGE_SIZE : page_num * _AUDIT_PAGE_SIZE]

    body_rows = []
    for row in page_rows:
        action_label, pill_cls = _AUDIT_ACTION_LABELS.get(row["action"], (row["action"], "update"))
        entity_label = _AUDIT_ENTITY_LABELS.get(row["entity_type"], row["entity_type"])
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
        body_rows.append(f"""
            <tr>
              <td class="audit-col-time">{format_dt(row['created_at'])}</td>
              <td class="audit-col-actor">{html.escape(row['actor_display_name'] or row['actor_username'] or row['actor_name'] or 'Систем')}</td>
              <td class="audit-col-action"><span class="audit-pill {pill_cls}">{html.escape(action_label)}</span></td>
              <td class="audit-col-department">{html.escape(row['department_name'] or '—')}</td>
              <td class="audit-col-details">{detail_html}</td>
            </tr>
        """)

    # Pagination controls
    def _audit_page_url(p):
        parts_q = []
        if search_q:
            parts_q.append(f"q={quote(search_q)}")
        if not search_q:
            parts_q += [f"year={sel_year}", f"month={sel_month}"]
        parts_q.append(f"page={p}")
        return "/audit?" + "&".join(parts_q)

    pagination_html = ""
    if total_pages > 1:
        prev_link = f'<a class="button-link ghost small" href="{_audit_page_url(page_num - 1)}">← Өмнөх</a>' if page_num > 1 else ""
        next_link = f'<a class="button-link ghost small" href="{_audit_page_url(page_num + 1)}">Дараах →</a>' if page_num < total_pages else ""
        pagination_html = f'<div class="audit-pagination">{prev_link}<span class="muted">{page_num} / {total_pages} хуудас</span>{next_link}</div>'

    month_names = ["", "1-р сар", "2-р сар", "3-р сар", "4-р сар", "5-р сар", "6-р сар",
                   "7-р сар", "8-р сар", "9-р сар", "10-р сар", "11-р сар", "12-р сар"]
    # Build year options from available months
    available_years = sorted({yr for yr, _, _ in available_months}, reverse=True) or [now_d.year]
    available_month_nums = sorted({mo for yr, mo, _ in available_months if yr == sel_year}) or list(range(1, 13))

    year_options = "".join(
        f'<option value="{yr}" {"selected" if yr == sel_year else ""}>{yr} он</option>'
        for yr in available_years
    )
    month_options_html = "".join(
        f'<option value="{mo}" {"selected" if mo == sel_month else ""}>{month_names[mo]}</option>'
        for mo in available_month_nums
    )

    count_suffix = " (бүх хугацаа)" if like else ""
    count_label = f"{total_count} бичлэг{count_suffix}" if rows else "Бичлэг олдсонгүй"
    no_rows_msg = "Хайлтын үр дүн олдсонгүй." if like else "Энэ сард бичлэг алга."
    body = f"""
    <section class="panel">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap">
        <h1>Аудит лог</h1>
      </div>
      <form class="audit-filter-form" method="get" action="/audit">
        <div class="audit-filter-row">
          <select name="year" class="audit-month-select" onchange="this.form.submit()">
            {year_options}
          </select>
          <select name="month" class="audit-month-select" onchange="this.form.submit()">
            {month_options_html}
          </select>
          <div class="reg-search-wrap" style="flex:1;min-width:160px">
            <input type="text" name="q" id="audit-q" class="audit-search-input"
                   value="{html.escape(search_q)}"
                   placeholder="Хэрэглэгч, нэр, и-мэйлээр хайх... (2+ тэмдэгт)"
                   autocomplete="off"
                   oninput="auditSuggest(this)"
                   onkeydown="auditSuggestKey(event)"
                   onblur="setTimeout(function(){{auditSuggestHide()}},180)">
            <div class="reg-search-dropdown" id="audit-suggest-dd" hidden></div>
          </div>
          <button type="submit">Хайх</button>
        </div>
      </form>
      <p class="muted">{count_label}.</p>
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
          <tbody>{''.join(body_rows) if body_rows else f'<tr><td colspan="5" class="muted">{no_rows_msg}</td></tr>'}</tbody>
        </table>
      </div>
      {pagination_html}
    </section>
    <script>
    (function() {{
      var AUDIT_USERS = {users_json};
      window.auditSuggest = function(input) {{
        var q = input.value.trim().toLowerCase();
        var dd = document.getElementById('audit-suggest-dd');
        if (!dd) return;
        if (q.length < 2) {{ dd.setAttribute('hidden', ''); dd.innerHTML = ''; return; }}
        var results = AUDIT_USERS.filter(function(u) {{
          return (u.label && u.label.toLowerCase().indexOf(q) !== -1) ||
                 (u.val && u.val.toLowerCase().indexOf(q) !== -1);
        }}).slice(0, 8);
        if (!results.length) {{ dd.setAttribute('hidden', ''); dd.innerHTML = ''; return; }}
        dd.innerHTML = results.map(function(u) {{
          var safeVal = (u.val || '').replace(/"/g, '&quot;').replace(/</g, '&lt;');
          var safeLabel = (u.label || '').replace(/</g, '&lt;');
          return '<div class="reg-search-item" data-val="' + safeVal + '" onclick="auditSuggestSelect(this.dataset.val)">'
            + '<span class="reg-search-col">' + safeLabel + '</span>'
            + ' <span class="reg-search-val" style="font-size:0.75rem;color:var(--muted)">' + safeVal + '</span></div>';
        }}).join('');
        dd.removeAttribute('hidden');
      }};
      window.auditSuggestHide = function() {{
        var dd = document.getElementById('audit-suggest-dd');
        if (dd) dd.setAttribute('hidden', '');
      }};
      window.auditSuggestSelect = function(val) {{
        var inp = document.getElementById('audit-q');
        if (inp) {{ inp.value = val; auditSuggestHide(); inp.focus(); }}
      }};
      window.auditSuggestKey = function(e) {{
        var dd = document.getElementById('audit-suggest-dd');
        if (!dd || dd.hasAttribute('hidden')) return;
        var items = dd.querySelectorAll('.reg-search-item');
        var active = dd.querySelector('.reg-search-item.active');
        var idx = -1;
        items.forEach(function(el, i) {{ if (el === active) idx = i; }});
        if (e.key === 'ArrowDown') {{
          e.preventDefault();
          var next = items[idx + 1] || items[0];
          if (active) active.classList.remove('active');
          if (next) next.classList.add('active');
        }} else if (e.key === 'ArrowUp') {{
          e.preventDefault();
          var prev = items[idx - 1] || items[items.length - 1];
          if (active) active.classList.remove('active');
          if (prev) prev.classList.add('active');
        }} else if (e.key === 'Enter') {{
          if (active) {{ e.preventDefault(); auditSuggestSelect(active.dataset.val || ''); }}
        }} else if (e.key === 'Escape') {{
          auditSuggestHide();
        }}
      }};
    }})();
    </script>
    """
    return render_page("Аудит лог", user, body, notice)


def _parse_flexible_dt(s):
    if not s:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y/%m/%d",
    ):
        try:
            return dt.datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    return None


def compute_resolution_time(reported_str, closed_str):
    start = _parse_flexible_dt(reported_str)
    end = _parse_flexible_dt(closed_str)
    if not start or not end or end < start:
        return ""
    total_minutes = int((end - start).total_seconds() // 60)
    hours = total_minutes // 60
    minutes = total_minutes % 60
    return f"{hours}ц {minutes:02d}м"


def resolve_computed_field(field_name, entry):
    if field_name == "resolution_time":
        return compute_resolution_time(entry["detected_date"], entry["closed"])
    return ""


def generate_incident_id(conn, register):
    year = now_utc().year
    count = conn.execute(
        f"SELECT COUNT(*) AS n FROM {register['table']} WHERE strftime('%Y', created_at) = ?",
        (str(year),),
    ).fetchone()["n"]
    return f"INC-{year}-{(count + 1):03d}"


def render_attachment_form(action, register, values, error="", submit_label="Хадгалах", notice=""):
    source = dict(values or {})
    inputs = []
    for name, label, required, field_type in register["fields"]:
        if field_type in ("auto", "computed"):
            continue
        raw = source.get(name, "") or ""
        value = html.escape(str(raw))
        required_attr = " required" if required else ""
        if field_type.startswith("select:"):
            opts = field_type[7:].split(",")
            options = '<option value="">— сонгох —</option>' + "".join(
                f'<option value="{html.escape(o)}"{" selected" if raw == o else ""}>{html.escape(o)}</option>'
                for o in opts
            )
            field = f'<select name="{name}"{required_attr}>{options}</select>'
        elif field_type == "textarea":
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
      {fmt_notice(notice)}
      {fmt_error(error)}
      <form method="post" action="{action}" class="asset-form">
        {''.join(inputs)}
        <div class="actions"><button type="submit">{submit_label}</button></div>
      </form>
    </section>
    """


ZORCHLIN_XLSX_FIELDS = [
    (4, "detected_date"),
    (5, "occurred_date"),
    (6, "reported_by"),
    (7, "system_location"),
    (8, "incident_type"),
    (9, "severity"),
    (10, "l1_started"),
    (11, "l2"),
    (12, "l3"),
    (13, "closed"),
    # row 14 = resolution_time (computed, skip)
    (15, "sla_violated"),
    (16, "root_cause"),
    (17, "description"),
]


def _format_xlsx_cell(value):
    if value is None:
        return ""
    if isinstance(value, dt.datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    if isinstance(value, dt.date):
        return value.strftime("%Y-%m-%d")
    if isinstance(value, dt.time):
        return value.strftime("%H:%M")
    return str(value).strip()


def parse_zorchlin_xlsx(file_bytes):
    wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
    ws = wb.active
    values = {}
    for row_num, field_name in ZORCHLIN_XLSX_FIELDS:
        cell = ws.cell(row=row_num, column=2)
        values[field_name] = _format_xlsx_cell(cell.value)
    return values


def zorchlin_new_page(user, register, error=""):
    slug = html.escape(register["slug"])
    manual_inputs = []
    for name, label, required, field_type in register["fields"]:
        if field_type in ("auto", "computed"):
            continue
        required_attr = " required" if required else ""
        if field_type.startswith("select:"):
            opts = field_type[7:].split(",")
            options = '<option value="">— сонгох —</option>' + "".join(
                f'<option value="{html.escape(o)}">{html.escape(o)}</option>' for o in opts
            )
            field = f'<select name="{name}"{required_attr}>{options}</select>'
        elif field_type == "textarea":
            field = f'<textarea name="{name}"{required_attr}></textarea>'
        else:
            field = f'<input type="text" name="{name}"{required_attr}>'
        manual_inputs.append(f"<label>{html.escape(label)}{field}</label>")
    body = f"""
    <section class="panel">
      <div class="heading-row">
        <div>
          <h1>{html.escape(register['title'])}</h1>
          <p class="muted">Шинэ зөрчил нэмэх</p>
        </div>
        <a class="button-link ghost" href="/admin-docs/registers/{slug}">Жагсаалт руу буцах</a>
      </div>
      {fmt_error(error)}
      <h2 style="font-size:1rem;margin-bottom:10px">Excel загваараар оруулах</h2>
      <form method="post" action="/admin-docs/registers/{slug}/xlsx-preview" enctype="multipart/form-data" class="stack-form">
        <p class="muted" style="margin:0">Excel загварыг татаж аваад бөглөсний дараа оруулна уу.</p>
        <label>Excel файл (.xlsx)<input type="file" name="xlsx_file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" required></label>
        <div class="actions"><button type="submit">Файл унших ба урьдчилан харах</button></div>
      </form>
      <div class="xlsx-or-divider">эсвэл</div>
      <details class="xlsx-manual-toggle">
        <summary>Гараар бөглөх</summary>
        <form method="post" action="/admin-docs/registers/{slug}/new" class="asset-form" style="margin-top:16px">
          {''.join(manual_inputs)}
          <div class="actions"><button type="submit">Хадгалах</button></div>
        </form>
      </details>
    </section>
    """
    return render_page(register["title"], user, body)


def validate_attachment_form(form, register):
    values = {}
    for field_name, label, required, field_type in register["fields"]:
        if field_type in ("auto", "computed"):
            continue
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
          {f'<a class="button-link ghost" href="/admin-docs/registers/{html.escape(register["slug"])}/export.xlsx">Excel татах</a>' if register['slug'] == 'zorchlin-burtgel' and is_superadmin(user) else ''}
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
    rows = [f"""
        <tr>
          <th>№</th>
          <td>{entry['id']}</td>
        </tr>"""]
    for field_name, label, _, field_type in register["fields"]:
        if field_type == "computed":
            raw = resolve_computed_field(field_name, entry)
        else:
            raw = entry[field_name]
        value = format_multiline(raw) if raw else '<span class="muted">—</span>'
        rows.append(f"""
        <tr>
          <th>{html.escape(label)}</th>
          <td>{value}</td>
        </tr>""")
    rows.append(f"""
        <tr>
          <th>Сүүлд өөрчилсөн</th>
          <td>{format_dt(entry['updated_at'])}</td>
        </tr>""")
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
      <table class="register-detail-table">
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>
    """
    return render_page(register["title"], user, body, notice)


def validate_asset_form(form, user, permissions, existing_asset=None):
    values = {}
    for field, label, required in ASSET_FIELDS:
        if field in ASSET_COMPUTED_FIELDS:
            continue
        editable = can_edit_field(user, permissions, field)
        if editable:
            value = normalize_text(form.get(field))
            if field in {"has_personal_data", "has_sensitive_data"}:
                value = normalize_flag(value)
            if field in DROPDOWN_OPTIONS and value:
                valid_values = {
                    (o[1] if isinstance(o, tuple) else o)
                    for o in DROPDOWN_OPTIONS[field]
                }
                if value not in valid_values:
                    return None, f"{label} талбарын утга буруу байна."
        else:
            value = normalize_text((existing_asset or {}).get(field))
        if required and editable and not value:
            return None, f"{label} талбарыг бөглөнө үү."
        values[field] = value
    # Auto-compute asset_value and asset_category
    asset_val = compute_asset_value(
        values.get("confidentiality", ""),
        values.get("integrity_impact", ""),
        values.get("availability_impact", ""),
    )
    values["asset_value"] = asset_val
    values["asset_category"] = compute_asset_category(asset_val)
    # review_frequency: admin-only editable
    if is_admin_or_above(user):
        freq = normalize_text(form.get("review_frequency"))
        if freq and freq not in FREQUENCY_OPTIONS:
            return None, f"Хянах давтамжийн утга буруу байна: {freq}"
        values["review_frequency"] = freq
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
    _req.form_cache = None
    _req.csrf_token = ""
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()
    query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
    conn = get_db()
    user = get_current_user(environ, conn)
    if user and user["session_id"]:
        _set_csrf(str(user["session_id"]))

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
        logo_path = BASE_DIR / "dico_logo.png"
        if logo_path.exists():
            data = logo_path.read_bytes()
            start_response("200 OK", [("Content-Type", "image/png"), ("Content-Length", str(len(data))), ("Cache-Control", "public, max-age=86400")])
            return [data]
        start_response("204 No Content", [("Content-Length", "0")])
        return [b""]

    # CSRF check: all authenticated URL-encoded POST requests must carry a valid token
    content_type = environ.get("CONTENT_TYPE", "")
    if method == "POST" and user and "multipart/form-data" not in content_type:
        form = parse_post(environ)
        if not _verify_csrf(form):
            conn.close()
            return response(start_response, "403 Forbidden", error_500_page())

    if path == "/":
        conn.close()
        return redirect(start_response, "/dashboard" if user else "/login")

    if path == "/auth/azure" and method == "GET":
        if not AZURE_TENANT_ID or not AZURE_CLIENT_ID or not AZURE_REDIRECT_URI:
            conn.close()
            return redirect(start_response, "/login?notice=" + quote("Azure нэвтрэлт тохируулагдаагүй байна."))
        params = urlencode({
            "client_id": AZURE_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": AZURE_REDIRECT_URI,
            "response_mode": "query",
            "scope": "openid email profile",
        })
        conn.close()
        return redirect(start_response, f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/authorize?{params}")

    if path == "/auth/azure/callback" and method == "GET":
        error_param = qs_value(query, "error")
        code = qs_value(query, "code")
        if error_param or not code:
            record_audit(conn, None, "login_failed", "session", details=f"Azure OAuth алдаа: {error_param or 'code дутуу'}")
            conn.commit()
            conn.close()
            return response(start_response, "403 Forbidden", no_access_page())
        try:
            token_data = urlencode({
                "grant_type": "authorization_code",
                "client_id": AZURE_CLIENT_ID,
                "client_secret": AZURE_CLIENT_SECRET,
                "redirect_uri": AZURE_REDIRECT_URI,
                "code": code,
            }).encode()
            token_req = _urllib_request.Request(
                f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token",
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with _urllib_request.urlopen(token_req, timeout=15) as resp:
                token_json = json.loads(resp.read())
            access_token = token_json.get("access_token", "")
            if not access_token:
                raise ValueError("no access_token")
            me_req = _urllib_request.Request(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            with _urllib_request.urlopen(me_req, timeout=15) as resp:
                me = json.loads(resp.read())
            email = (me.get("mail") or me.get("userPrincipalName") or "").strip().lower()
            display_name = me.get("displayName", "")
            if not email:
                raise ValueError("no email")
        except Exception as exc:
            record_audit(conn, None, "login_failed", "session", details=f"Azure callback алдаа: {exc}")
            conn.commit()
            conn.close()
            return response(start_response, "403 Forbidden", no_access_page())
        candidate = conn.execute(
            """
            SELECT users.*, departments.slug AS department_slug, departments.name AS department_name
            FROM users
            LEFT JOIN departments ON departments.id = users.department_id
            WHERE lower(users.email) = ? AND users.is_active = 1
            """,
            (email,),
        ).fetchone()
        if not candidate:
            record_audit(conn, None, "login_failed", "session", details=f"Azure: бүртгэлгүй и-мэйл — {email}")
            conn.commit()
            conn.close()
            return response(start_response, "403 Forbidden", no_access_page())
        conn.execute("UPDATE users SET last_login_at = ?, display_name = ? WHERE id = ?", (now_utc().isoformat(), display_name, candidate["id"]))
        session_id = create_session(conn, candidate["id"])
        record_audit(conn, candidate["id"], "login", "session", entity_id=session_id, department_id=candidate["department_id"], details="Azure-аар нэвтэрлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/dashboard", headers=[session_cookie_header(session_id)])

    if path == "/auth/portal-sso" and method == "GET":
        token = qs_value(query, "token")
        if not token:
            record_audit(conn, None, "login_failed", "session", details="SSO: токен дутуу.")
            conn.commit()
            conn.close()
            return response(start_response, "403 Forbidden", no_access_page())
        try:
            payload = decode_portal_jwt(token)
        except ValueError:
            record_audit(conn, None, "login_failed", "session", details="SSO: хүчингүй токен.")
            conn.commit()
            conn.close()
            return response(start_response, "403 Forbidden", no_access_page())
        email = payload["email"].lower().strip()
        candidate = conn.execute(
            """
            SELECT users.*, departments.slug AS department_slug, departments.name AS department_name
            FROM users
            LEFT JOIN departments ON departments.id = users.department_id
            WHERE lower(users.email) = ? AND users.is_active = 1
            """,
            (email,),
        ).fetchone()
        if not candidate:
            record_audit(conn, None, "login_failed", "session", details=f"SSO: бүртгэлгүй и-мэйл — {email}")
            conn.commit()
            conn.close()
            return response(start_response, "403 Forbidden", no_access_page())
        display_name = payload.get("displayName", "")
        conn.execute(
            "UPDATE users SET last_login_at = ?, display_name = ? WHERE id = ?",
            (now_utc().isoformat(), display_name, candidate["id"]),
        )
        session_id = create_session(conn, candidate["id"])
        record_audit(conn, candidate["id"], "login", "session", entity_id=session_id, department_id=candidate["department_id"], details="Порталаар нэвтэрлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/dashboard", headers=[session_cookie_header(session_id)])

    if path == "/login":
        if method == "POST":
            form = parse_post(environ)
            identifier = normalize_text(form.get("username", ""))
            password = form.get("password", "")
            candidate = conn.execute(
                """
                SELECT users.*, departments.slug AS department_slug, departments.name AS department_name
                FROM users
                LEFT JOIN departments ON departments.id = users.department_id
                WHERE (lower(users.username) = lower(?) OR lower(users.email) = lower(?))
                  AND users.is_active = 1
                """,
                (identifier, identifier),
            ).fetchone()
            if not candidate or not candidate["password_hash"] or not verify_password(password, candidate["password_hash"]):
                record_audit(conn, None, "login_failed", "session", details=f"Нууц үгээр нэвтрэх амжилтгүй: {identifier}")
                conn.commit()
                conn.close()
                return response(start_response, "401 Unauthorized", login_form(error="И-мэйл/хэрэглэгчийн нэр эсвэл нууц үг буруу байна."))
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_utc().isoformat(), candidate["id"]))
            session_id = create_session(conn, candidate["id"])
            record_audit(conn, candidate["id"], "login", "session", entity_id=session_id, department_id=candidate["department_id"], details="Нууц үгээр нэвтэрлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/dashboard", headers=[session_cookie_header(session_id)])
        page = login_form(notice=qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/set-password":
        token = qs_value(query, "token") if method == "GET" else parse_post(environ).get("token", "")
        if method == "GET":
            if not token:
                conn.close()
                return redirect(start_response, "/login?notice=" + quote("Холбоос хүчингүй байна."))
            row = conn.execute(
                "SELECT * FROM auth_tokens WHERE token = ? AND token_type = 'set_password' AND used = 0", (token,)
            ).fetchone()
            if not row or _parse_dt(row["expires_at"]) < now_utc():
                conn.close()
                return response(start_response, "400 Bad Request", set_password_page("", error="Холбоос хугацаа дууссан эсвэл хүчингүй байна. Администратороос дахин урилга авна уу."))
            conn.close()
            return response(start_response, "200 OK", set_password_page(token))
        form = parse_post(environ)
        token = form.get("token", "")
        new_pw = form.get("new_password", "")
        confirm_pw = form.get("confirm_password", "")
        tok_row = consume_auth_token(conn, token, "set_password")
        if not tok_row:
            conn.close()
            return response(start_response, "400 Bad Request", set_password_page(token, error="Холбоос хугацаа дууссан эсвэл хүчингүй байна."))
        if new_pw != confirm_pw:
            conn.execute("UPDATE auth_tokens SET used = 0 WHERE id = ?", (tok_row["id"],))
            conn.close()
            return response(start_response, "400 Bad Request", set_password_page(token, error="Нууц үг таарахгүй байна."))
        policy_err = validate_password_policy(new_pw)
        if policy_err:
            conn.execute("UPDATE auth_tokens SET used = 0 WHERE id = ?", (tok_row["id"],))
            conn.close()
            return response(start_response, "400 Bad Request", set_password_page(token, error=policy_err))
        conn.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = ?, must_change_password = 0, last_login_at = ? WHERE id = ?",
            (hash_password(new_pw), now_utc().isoformat(), now_utc().isoformat(), tok_row["user_id"]),
        )
        candidate = conn.execute(
            "SELECT users.*, departments.slug AS department_slug, departments.name AS department_name FROM users LEFT JOIN departments ON departments.id = users.department_id WHERE users.id = ?",
            (tok_row["user_id"],),
        ).fetchone()
        session_id = create_session(conn, tok_row["user_id"])
        record_audit(conn, tok_row["user_id"], "change_password", "user", entity_id=tok_row["user_id"], department_id=candidate["department_id"] if candidate else None, target_user_id=tok_row["user_id"], details="Нууц үг анх удаа үүсгэлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/dashboard", headers=[session_cookie_header(session_id)])

    if path == "/forgot-password":
        if method == "POST":
            form = parse_post(environ)
            email_input = normalize_text(form.get("email", "")).lower()
            candidate = conn.execute(
                "SELECT * FROM users WHERE lower(email) = ? AND is_active = 1", (email_input,)
            ).fetchone()
            if candidate:
                otp = create_otp(conn, candidate["id"])
                conn.commit()
                send_otp_email(candidate["email"], candidate["display_name"] or "", otp)
            conn.close()
            return redirect(start_response, "/reset-password?email=" + quote(email_input))
        conn.close()
        return response(start_response, "200 OK", forgot_password_page(notice=qs_value(query, "notice")))

    if path == "/reset-password":
        email_param = qs_value(query, "email") if method == "GET" else parse_post(environ).get("email", "")
        if method == "GET":
            conn.close()
            return response(start_response, "200 OK", reset_password_page(email_param))
        form = parse_post(environ)
        email_input = normalize_text(form.get("email", "")).lower()
        otp_input = form.get("otp", "").strip()
        new_pw = form.get("new_password", "")
        confirm_pw = form.get("confirm_password", "")
        candidate = conn.execute(
            "SELECT * FROM users WHERE lower(email) = ? AND is_active = 1", (email_input,)
        ).fetchone()
        if not candidate:
            conn.close()
            return response(start_response, "400 Bad Request", reset_password_page(email_input, error="И-мэйл хаяг олдсонгүй."))
        tok_row = consume_auth_token(conn, otp_input, "otp")
        if not tok_row or tok_row["user_id"] != candidate["id"]:
            conn.close()
            return response(start_response, "400 Bad Request", reset_password_page(email_input, error="Код буруу эсвэл хугацаа дууссан байна."))
        if new_pw != confirm_pw:
            conn.close()
            return response(start_response, "400 Bad Request", reset_password_page(email_input, error="Нууц үг таарахгүй байна."))
        policy_err = validate_password_policy(new_pw)
        if policy_err:
            conn.close()
            return response(start_response, "400 Bad Request", reset_password_page(email_input, error=policy_err))
        conn.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = ?, must_change_password = 0, last_login_at = ? WHERE id = ?",
            (hash_password(new_pw), now_utc().isoformat(), now_utc().isoformat(), candidate["id"]),
        )
        session_id = create_session(conn, candidate["id"])
        record_audit(conn, candidate["id"], "change_password", "user", entity_id=candidate["id"], department_id=candidate["department_id"], target_user_id=candidate["id"], details="OTP-оор нууц үг сэргээлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/dashboard", headers=[session_cookie_header(session_id)])


    if not user:
        conn.close()
        return redirect(start_response, "/login")

    if path == "/logout" and method == "POST":
        record_audit(conn, user["id"], "logout", "session", entity_id=user["session_id"], department_id=user["department_id"], details="Хэрэглэгч системээс гарлаа.")
        clear_session(conn, environ)
        conn.commit()
        conn.close()
        return redirect(start_response, "/login", headers=[session_cookie_header("expired", 0)])

    if path == "/dashboard":
        page = dashboard_page(conn, user, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/departments":
        page = departments_page(conn, user, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/departments/create":
        if not is_superadmin(user):
            conn.close()
            return forbidden(start_response)
        if method == "GET":
            page = render_page("Хэлтэс нэмэх", user, department_create_page())
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        name = (form.get("name") or "").strip()
        code = (form.get("code") or "").strip().upper()
        if not name or not code:
            page = render_page("Хэлтэс нэмэх", user, department_create_page(error="Нэр болон код заавал оруулна уу.", values=form))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        slug = slugify(name)
        existing = conn.execute("SELECT id FROM departments WHERE slug = ? OR code = ?", (slug, code)).fetchone()
        if existing:
            page = render_page("Хэлтэс нэмэх", user, department_create_page(error="Ийм нэртэй эсвэл кодтой хэлтэс аль хэдийн байна.", values=form))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        timestamp = now_utc().isoformat()
        conn.execute("INSERT INTO departments(code, slug, name) VALUES (?, ?, ?)", (code, slug, name))
        dept_id = conn.execute("SELECT id FROM departments WHERE slug = ?", (slug,)).fetchone()["id"]
        for field_name, _, _ in ASSET_FIELDS:
            conn.execute(
                "INSERT OR IGNORE INTO department_column_permissions(department_id, field_name, can_edit, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
                (dept_id, field_name, timestamp, timestamp),
            )
        record_audit(conn, user["id"], "create", "department", entity_id=dept_id, details=f"{name} хэлтэс нэмэгдлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/departments?notice=" + quote(f"{name} хэлтэс нэмэгдлээ."))

    if path.startswith("/departments/") and path.endswith("/edit"):
        if not is_superadmin(user):
            conn.close()
            return forbidden(start_response)
        slug = unquote(path[len("/departments/"):-len("/edit")])
        department = get_department(conn, slug)
        if not department:
            conn.close()
            return not_found(start_response)
        if method == "GET":
            page = render_page("Хэлтэс засах", user, department_edit_page(department))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        name = (form.get("name") or "").strip()
        code = (form.get("code") or "").strip().upper()
        if not name or not code:
            page = render_page("Хэлтэс засах", user, department_edit_page(department, error="Нэр болон код заавал оруулна уу.", values=form))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        conflict = conn.execute(
            "SELECT id FROM departments WHERE (code = ? OR name = ?) AND id != ?",
            (code, name, department["id"]),
        ).fetchone()
        if conflict:
            page = render_page("Хэлтэс засах", user, department_edit_page(department, error="Ийм нэртэй эсвэл кодтой хэлтэс аль хэдийн байна.", values=form))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        conn.execute("UPDATE departments SET name = ?, code = ? WHERE id = ?", (name, code, department["id"]))
        record_audit(conn, user["id"], "update", "department", entity_id=department["id"], details=f"{department['name']} → {name} хэлтэс шинэчлэгдлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/departments?notice=" + quote(f"{name} хэлтэс шинэчлэгдлээ."))

    if path.startswith("/departments/") and path.endswith("/delete"):
        if not is_superadmin(user):
            conn.close()
            return forbidden(start_response)
        if method != "POST":
            conn.close()
            return redirect(start_response, "/departments")
        slug = unquote(path[len("/departments/"):-len("/delete")])
        department = get_department(conn, slug)
        if not department:
            conn.close()
            return not_found(start_response)
        name = department["name"]
        conn.execute("DELETE FROM departments WHERE id = ?", (department["id"],))
        record_audit(conn, user["id"], "delete", "department", entity_id=department["id"], details=f"{name} хэлтэс устгагдлаа.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/departments?notice=" + quote(f"{name} хэлтэс устгагдлаа."))

    if path == "/review-timer/reset":
        if not is_superadmin(user):
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
        if not is_admin_or_above(user):
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
        if not is_admin_or_above(user):
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
        if len(parts) == 4 and parts[2] == "rows" and parts[3] != "new" and method == "GET":
            row = get_custom_register_row(conn, register["id"], parts[3])
            if not row:
                conn.close()
                return not_found(start_response)
            columns = list_custom_register_columns(conn, register["id"])
            values = get_custom_row_values(conn, row["id"])
            page = custom_register_row_detail_page(user, register, columns, row, values)
            conn.close()
            return response(start_response, "200 OK", page)
        if len(parts) == 5 and parts[2] == "columns" and parts[4] == "brief-toggle" and method == "POST":
            column = conn.execute(
                "SELECT * FROM custom_register_columns WHERE id = ? AND register_id = ?",
                (parts[3], register["id"]),
            ).fetchone()
            if not column:
                conn.close()
                return not_found(start_response)
            form = parse_post(environ)
            if form.get("enabled") == "1":
                conn.execute(
                    "INSERT OR IGNORE INTO custom_register_brief_columns(register_id, column_id) VALUES (?, ?)",
                    (register["id"], column["id"]),
                )
            else:
                conn.execute(
                    "DELETE FROM custom_register_brief_columns WHERE register_id = ? AND column_id = ?",
                    (register["id"], column["id"]),
                )
            conn.commit()
            conn.close()
            return redirect(start_response, f"/custom-registers/{quote(register['slug'])}")
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
        if not can_manage_users(user):
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
        if not is_superadmin(user):
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
        if not is_admin_or_above(user):
            conn.close()
            return forbidden(start_response)
        overview = render_admin_documents_overview(conn)
        page = render_page("Админ баримтууд", user, overview)
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/admin-doc-categories/create":
        if not is_admin_or_above(user):
            conn.close()
            return forbidden(start_response)
        if method != "POST":
            conn.close()
            return redirect(start_response, "/admin-docs")
        form = parse_post(environ)
        category, error = create_admin_document_category(conn, form.get("name"))
        if error:
            conn.close()
            return redirect(start_response, "/admin-docs?notice=" + quote(error))
        record_audit(conn, user["id"], "create", "admin_document_category", entity_id=category["id"], details=f"{category['name']} ангилал нэмлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/admin-docs?notice=" + quote("Баримтын ангилал нэмэгдлээ."))

    if path.startswith("/admin-docs/registers/"):
        if not is_admin_or_above(user):
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

        if len(parts) == 4 and parts[3] == "export.xlsx" and method == "GET":
            if register["slug"] == "zorchlin-burtgel" and not is_superadmin(user):
                conn.close()
                return forbidden(start_response)
            matrix = attachment_register_export_matrix(conn, register)
            record_audit(conn, user["id"], "download_excel", register["entity_type"], details=f"{register['title']} бүртгэлийг Excel файлаар татлаа.")
            conn.commit()
            conn.close()
            payload = build_xlsx_payload(register["title"], matrix)
            filename = f"{register['slug']}.xlsx"
            return send_bytes(start_response, payload, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename)

        if len(parts) == 4 and parts[3] == "xlsx-preview" and method == "POST":
            if register["slug"] != "zorchlin-burtgel":
                conn.close()
                return not_found(start_response)
            form = parse_multipart(environ)
            xlsx_item = form["xlsx_file"] if "xlsx_file" in form else None
            if xlsx_item is None or not getattr(xlsx_item, "filename", None):
                page = zorchlin_new_page(user, register, error="Excel файл оруулаагүй байна.")
                conn.close()
                return response(start_response, "400 Bad Request", page)
            if _upload_too_large(xlsx_item, _MAX_XLSX_BYTES):
                page = zorchlin_new_page(user, register, error="Файлын хэмжээ 5 МБ-аас хэтрэхгүй байх ёстой.")
                conn.close()
                return response(start_response, "400 Bad Request", page)
            try:
                values = parse_zorchlin_xlsx(xlsx_item.file.read())
            except Exception:
                page = zorchlin_new_page(user, register, error="Excel файлыг унших боломжгүй байна. Зөв загвар ашиглаж байгаа эсэхийг шалгаарай.")
                conn.close()
                return response(start_response, "400 Bad Request", page)
            save_path = f"/admin-docs/registers/{register['slug']}/new"
            page = render_page(
                register["title"],
                user,
                render_attachment_form(save_path, register, values, notice="Excel файлаас уншсан өгөгдөл. Доорх талбаруудыг шалгаад Хадгалах дарна уу."),
            )
            conn.close()
            return response(start_response, "200 OK", page)

        if len(parts) == 4 and parts[3] == "new":
            if method == "GET":
                if register["slug"] == "zorchlin-burtgel":
                    page = zorchlin_new_page(user, register)
                else:
                    page = render_page(register["title"], user, render_attachment_form(path, register, {}))
                conn.close()
                return response(start_response, "200 OK", page)
            form = parse_post(environ)
            values, error = validate_attachment_form(form, register)
            if error:
                page = render_page(register["title"], user, render_attachment_form(path, register, form, error=error))
                conn.close()
                return response(start_response, "400 Bad Request", page)
            for field_name, _, _, field_type in register["fields"]:
                if field_type == "auto":
                    values[field_name] = generate_incident_id(conn, register)
                elif field_type == "computed":
                    values[field_name] = ""
            timestamp = now_utc().isoformat()
            storable = [(fn, ft) for fn, _, _, ft in register["fields"] if ft != "computed"]
            columns = [fn for fn, _ in storable] + ["created_at", "updated_at"]
            placeholders = ", ".join(["?"] * len(columns))
            conn.execute(
                f"INSERT INTO {register['table']} ({', '.join(columns)}) VALUES ({placeholders})",
                [values[fn] for fn, _ in storable] + [timestamp, timestamp],
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
            assignments = ", ".join(
                f"{fn} = :{fn}" for fn, _, _, ft in register["fields"] if ft not in ("auto", "computed")
            )
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
        parts = [unquote(part) for part in path.strip("/").split("/")]
        if len(parts) < 2:
            conn.close()
            return not_found(start_response)
        category = admin_document_category_detail(conn, parts[1])
        if not category:
            conn.close()
            return not_found(start_response)
        _cat_is_public = dict(category).get("slug", "") in PUBLIC_DOC_CATEGORY_SLUGS
        if not is_admin_or_above(user) and not _cat_is_public:
            conn.close()
            return forbidden(start_response)
        if len(parts) == 2 and method == "GET":
            page = admin_document_category_page(conn, user, category, qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        if len(parts) == 3 and parts[2] == "rename" and method == "POST":
            form = parse_post(environ)
            error = rename_admin_document_category(conn, category, form.get("name"))
            if error:
                conn.close()
                return redirect(start_response, f"/admin-doc-categories/{category['id']}?notice=" + quote(error))
            record_audit(conn, user["id"], "update", "admin_document_category", entity_id=category["id"], details=f"{category['name']} ангиллын нэрийг шинэчиллээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, f"/admin-doc-categories/{category['id']}?notice=" + quote("Ангиллын нэр шинэчлэгдлээ."))
        if len(parts) == 3 and parts[2] == "delete" and method == "POST":
            conn.execute("DELETE FROM admin_document_category_links WHERE category_id = ?", (category["id"],))
            delete_admin_document_category(conn, category)
            record_audit(conn, user["id"], "delete", "admin_document_category", entity_id=category["id"], details=f"{category['name']} ангиллыг устгалаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/admin-docs?notice=" + quote("Ангилал устгагдлаа."))
        conn.close()
        return not_found(start_response)

    if path == "/admin-docs/manage":
        if not is_admin_or_above(user):
            conn.close()
            return forbidden(start_response)
        page = render_admin_docs_manage_page(conn, user, qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path.startswith("/admin-docs/preview-file/"):
        if not is_superadmin(user):
            conn.close()
            return forbidden(start_response)
        token = path.split("/admin-docs/preview-file/", 1)[1].strip("/")
        conn.close()
        if not token or not token.isalnum():
            return not_found(start_response)
        tmp_files = list(Path(tempfile.gettempdir()).glob(f"burtgel_preview_{token}*"))
        if not tmp_files:
            return not_found(start_response)
        return send_inline_file(start_response, tmp_files[0])

    if path == "/admin-docs/create":
        if not is_admin_or_above(user):
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
        has_file = upload is not None and bool(getattr(upload, "filename", ""))
        if not filename or not category_id:
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Файлын нэр болон ангилал оруулна уу."))
        category = get_admin_document_category(conn, category_id)
        if not category:
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Сонгосон ангилал олдсонгүй."))
        safe_name = Path(filename).name
        suffix = Path(safe_name).suffix.lower()
        if has_file:
            up_suffix = Path(str(upload.filename)).suffix.lower()
            if suffix not in allowed_admin_document_suffixes():
                if up_suffix in allowed_admin_document_suffixes():
                    safe_name = safe_name + up_suffix
                    suffix = up_suffix
                else:
                    conn.close()
                    return redirect(start_response, return_to + "?notice=" + quote("Зөвшөөрөгдсөн файл биш байна."))
        else:
            if suffix not in allowed_admin_document_suffixes():
                safe_name = safe_name + ".docx"
                suffix = ".docx"
        target_path = (DOCS_DIR / safe_name).resolve()
        try:
            target_path.relative_to(DOCS_DIR.resolve())
        except ValueError:
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Файлын нэр буруу байна."))
        if target_path.exists():
            conn.close()
            return redirect(start_response, return_to + "?notice=" + quote("Ийм нэртэй файл аль хэдийн байна."))
        if has_file:
            if _upload_too_large(upload, _MAX_PDF_BYTES):
                conn.close()
                return redirect(start_response, return_to + "?notice=" + quote("Файлын хэмжээ 20 МБ-аас хэтрэхгүй байх ёстой."))
            payload = upload.file.read()
            if not payload:
                conn.close()
                return redirect(start_response, return_to + "?notice=" + quote("Хоосон файл оруулах боломжгүй."))
            target_path.write_bytes(payload)
        elif suffix == ".docx":
            create_empty_docx(target_path)
        else:
            target_path.write_bytes(b"")
        set_admin_document_category(conn, safe_name, category["id"])
        record_audit(conn, user["id"], "create", "admin_document", entity_id=safe_name, details=f"{safe_name} файлыг {category['name']} ангилалд нэмлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, return_to + "?notice=" + quote("Админ файл нэмэгдлээ."))

    if path.startswith("/admin-docs/") and "/subfiles/" in path:
        after = path.split("/admin-docs/", 1)[1]
        if "/subfiles/" not in after:
            conn.close()
            return not_found(start_response)
        parent_encoded, sub_rest = after.split("/subfiles/", 1)
        parent_name = unquote(parent_encoded)
        file_path = resolve_admin_document(parent_name)
        if not file_path:
            conn.close()
            return not_found(start_response)
        _sf_public = _file_in_public_category(conn, file_path.name)
        if not is_admin_or_above(user) and not _sf_public:
            conn.close()
            return forbidden(start_response)
        view_url = f"/admin-docs/{quote(file_path.name)}"
        if sub_rest == "upload" and method == "POST":
            form = parse_multipart(environ)
            upload = form["subfile"] if "subfile" in form else None
            if upload is None or not getattr(upload, "filename", ""):
                conn.close()
                return redirect(start_response, view_url + "?notice=" + quote("Файл сонгоно уу."))
            orig_name = Path(str(upload.filename)).name
            up_suffix = Path(orig_name).suffix.lower()
            if up_suffix not in _allowed_subfile_suffixes():
                conn.close()
                return redirect(start_response, view_url + "?notice=" + quote("Зөвшөөрөгдөөгүй файлын төрөл."))
            if _upload_too_large(upload, _MAX_PDF_BYTES):
                conn.close()
                return redirect(start_response, view_url + "?notice=" + quote("Файлын хэмжээ 20 МБ-аас хэтрэхгүй байх ёстой."))
            payload = upload.file.read()
            if not payload:
                conn.close()
                return redirect(start_response, view_url + "?notice=" + quote("Хоосон файл оруулах боломжгүй."))
            stored_name = uuid.uuid4().hex + up_suffix
            (SUBFILES_DIR / stored_name).write_bytes(payload)
            now = now_utc().isoformat()
            conn.execute(
                "INSERT INTO admin_document_subfiles(parent_file_name, original_name, stored_name, uploaded_by, uploaded_at) VALUES(?,?,?,?,?)",
                (file_path.name, orig_name, stored_name, user["id"], now),
            )
            record_audit(conn, user["id"], "create", "admin_document_subfile", entity_id=file_path.name, details=f"{orig_name} дэд файл нэмэгдлээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, view_url + "?notice=" + quote(f"{orig_name} дэд файл нэмэгдлээ."))
        parts_sub = sub_rest.rstrip("/").split("/")
        if len(parts_sub) == 2 and parts_sub[1] in ("download", "delete", "raw", "view"):
            try:
                subfile_id = int(parts_sub[0])
            except ValueError:
                conn.close()
                return not_found(start_response)
            action = parts_sub[1]
            sf = get_subfile(conn, subfile_id)
            if not sf or sf["parent_file_name"] != file_path.name:
                conn.close()
                return not_found(start_response)
            stored_path = SUBFILES_DIR / sf["stored_name"]
            if action == "view":
                page = admin_subfile_view_page(conn, user, file_path, sf)
                conn.close()
                return response(start_response, "200 OK", page)
            if action == "raw":
                if not stored_path.exists():
                    conn.close()
                    return not_found(start_response)
                conn.close()
                return send_inline_file(start_response, stored_path, download_name=sf["original_name"])
            if action == "download":
                if not stored_path.exists():
                    conn.close()
                    return not_found(start_response)
                record_audit(conn, user["id"], "download", "admin_document_subfile", entity_id=str(subfile_id), details=f"{sf['original_name']} дэд файл татагдлаа.")
                conn.commit()
                conn.close()
                return send_file(start_response, stored_path, download_name=sf["original_name"])
            if action == "delete":
                if method != "POST":
                    conn.close()
                    return redirect(start_response, view_url)
                stored_path.unlink(missing_ok=True)
                conn.execute("DELETE FROM admin_document_subfiles WHERE id = ?", (subfile_id,))
                record_audit(conn, user["id"], "delete", "admin_document_subfile", entity_id=str(subfile_id), details=f"{sf['original_name']} дэд файл устгагдлаа.")
                conn.commit()
                conn.close()
                return redirect(start_response, view_url + "?notice=" + quote(f"{sf['original_name']} устгагдлаа."))
        conn.close()
        return not_found(start_response)

    if path.startswith("/admin-docs/"):
        suffix = path.split("/admin-docs/", 1)[1]
        is_download = suffix.endswith("/download")
        is_replace = suffix.endswith("/replace")
        is_delete = suffix.endswith("/delete")
        is_category = suffix.endswith("/category")
        is_preview = suffix.endswith("/preview")
        is_confirm = suffix.endswith("/confirm-replace")
        is_embed = suffix.endswith("/embed")
        raw_name = (
            suffix[:-9] if is_download else
            suffix[:-8] if is_replace else
            suffix[:-7] if is_delete else
            suffix[:-9] if is_category else
            suffix[:-8] if is_preview else
            suffix[:-16] if is_confirm else
            suffix[:-6] if is_embed else
            suffix
        )
        file_path = resolve_admin_document(raw_name)
        if not file_path:
            conn.close()
            return not_found(start_response)
        try:
            file_path.relative_to(DOCS_DIR.resolve())
        except ValueError:
            conn.close()
            return forbidden(start_response)
        _doc_public = _file_in_public_category(conn, file_path.name)
        # Non-admins may only GET public-category docs (view, embed, download)
        _read_only_action = not (is_replace or is_delete or is_category or is_preview or is_confirm)
        if not is_admin_or_above(user) and not (_doc_public and _read_only_action):
            conn.close()
            return forbidden(start_response)
        if is_embed:
            conn.close()
            return send_inline_file(start_response, file_path)
        if is_preview:
            if not is_superadmin(user):
                conn.close()
                return forbidden(start_response)
            if method != "POST":
                conn.close()
                return redirect(start_response, f"/admin-docs/{quote(file_path.name)}")
            form = parse_multipart(environ)
            upload = form["document"] if "document" in form else None
            if upload is None or not getattr(upload, "filename", ""):
                conn.close()
                return redirect(start_response, f"/admin-docs/{quote(file_path.name)}?notice=" + quote("Файл сонгоно уу."))
            up_suffix = Path(str(upload.filename)).suffix.lower()
            if up_suffix not in allowed_admin_document_suffixes():
                conn.close()
                return redirect(start_response, f"/admin-docs/{quote(file_path.name)}?notice=" + quote("Зөвшөөрөгдсөн файлын төрөл биш байна."))
            if _upload_too_large(upload, _MAX_PDF_BYTES):
                conn.close()
                return redirect(start_response, f"/admin-docs/{quote(file_path.name)}?notice=" + quote("Файлын хэмжээ 20 МБ-аас хэтрэхгүй байх ёстой."))
            payload = upload.file.read()
            if not payload:
                conn.close()
                return redirect(start_response, f"/admin-docs/{quote(file_path.name)}?notice=" + quote("Хоосон файл оруулах боломжгүй."))
            token = uuid.uuid4().hex
            tmp_path = Path(tempfile.gettempdir()) / f"burtgel_preview_{token}{up_suffix}"
            tmp_path.write_bytes(payload)
            page = admin_document_preview_page(conn, user, file_path, tmp_path, token)
            conn.close()
            return response(start_response, "200 OK", page)
        if is_confirm:
            if not is_superadmin(user):
                conn.close()
                return forbidden(start_response)
            if method != "POST":
                conn.close()
                return redirect(start_response, f"/admin-docs/{quote(file_path.name)}")
            form = parse_post(environ)
            token = (form.get("preview_token") or "").strip()
            view_url = f"/admin-docs/{quote(file_path.name)}"
            if not token or not token.isalnum():
                conn.close()
                return redirect(start_response, view_url + "?notice=" + quote("Баталгаажуулах токен буруу байна."))
            tmp_files = list(Path(tempfile.gettempdir()).glob(f"burtgel_preview_{token}*"))
            if not tmp_files:
                conn.close()
                return redirect(start_response, view_url + "?notice=" + quote("Урьдчилан харах файл олдсонгүй эсвэл хугацаа дууссан байна."))
            tmp_path = tmp_files[0]
            up_suffix = tmp_path.suffix.lower()
            if up_suffix != file_path.suffix.lower():
                tmp_path.unlink(missing_ok=True)
                conn.close()
                return redirect(start_response, view_url + "?notice=" + quote("Файлын төрөл таарахгүй байна."))
            edits_raw = (form.get("edits") or "").strip()
            if edits_raw and up_suffix == ".docx":
                apply_docx_edits(tmp_path, edits_raw)
            file_path.write_bytes(tmp_path.read_bytes())
            tmp_path.unlink(missing_ok=True)
            record_audit(conn, user["id"], "update", "admin_document", entity_id=file_path.name, details=f"{file_path.name} файлыг урьдчилан харагдацаар баталгаажуулж шинэчиллээ.")
            conn.commit()
            conn.close()
            return redirect(start_response, view_url + "?notice=" + quote("Файл амжилттай шинэчлэгдлээ."))
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
            if upload is None or not getattr(upload, "filename", ""):
                conn.close()
                return redirect(start_response, return_to + "?notice=" + quote("Файл сонгоно уу."))
            uploaded_name = str(upload.filename)
            if Path(uploaded_name).suffix.lower() != file_path.suffix.lower():
                conn.close()
                return redirect(start_response, return_to + "?notice=" + quote("Ижил төрлийн файл оруулна уу."))
            if _upload_too_large(upload, _MAX_PDF_BYTES):
                conn.close()
                return redirect(start_response, return_to + "?notice=" + quote("Файлын хэмжээ 20 МБ-аас хэтрэхгүй байх ёстой."))
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
        if not is_admin_or_above(user):
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
        if _upload_too_large(upload, _MAX_PDF_BYTES):
            conn.close()
            return redirect(start_response, "/departments?notice=" + quote("Файлын хэмжээ 20 МБ-аас хэтрэхгүй байх ёстой."))
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
            if not is_admin_or_above(user):
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
            if not is_admin_or_above(user):
                conn.close()
                return forbidden(start_response)
            if method != "POST":
                conn.close()
                return redirect(start_response, "/departments")
            form = parse_multipart(environ)
            upload = form["document"] if "document" in form else None
            if upload is None or not getattr(upload, "filename", ""):
                conn.close()
                return redirect(start_response, "/departments?notice=" + quote("PDF файл сонгоно уу."))
            if not str(upload.filename).lower().endswith(".pdf"):
                conn.close()
                return redirect(start_response, "/departments?notice=" + quote("Зөвхөн PDF файл оруулна уу."))
            if _upload_too_large(upload, _MAX_PDF_BYTES):
                conn.close()
                return redirect(start_response, "/departments?notice=" + quote("Файлын хэмжээ 20 МБ-аас хэтрэхгүй байх ёстой."))
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
        if not is_superadmin(user):
            conn.close()
            return forbidden(start_response)
        page = audit_page(conn, user, qs_value(query, "notice"), query=query)
        conn.close()
        return response(start_response, "200 OK", page)

    if path.startswith("/users/") and path.endswith("/reset-password"):
        if not can_manage_users(user):
            conn.close()
            return forbidden(start_response)
        user_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, user_id)
        if not target_user:
            conn.close()
            return not_found(start_response)
        if method == "GET":
            page = admin_reset_password_page(user, target_user, notice=qs_value(query, "notice"))
            conn.close()
            return response(start_response, "200 OK", page)
        temp_password = generate_temporary_password()
        conn.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = NULL, must_change_password = 1 WHERE id = ?",
            (hash_password(temp_password), user_id),
        )
        record_audit(conn, user["id"], "reset_password", "user", entity_id=user_id, department_id=target_user["department_id"], target_user_id=user_id, details=f"{target_user['username']} хэрэглэгчийн нууц үгийг админ reset хийлээ.")
        conn.commit()
        page = admin_reset_password_page(user, target_user, notice="Түр нууц үг амжилттай үүслээ.", temp_password=temp_password)
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/users/create":
        if not can_manage_users(user):
            conn.close()
            return forbidden(start_response)
        all_departments = list(conn.execute("SELECT * FROM departments ORDER BY name"))
        if method == "GET":
            page = render_page("Хэрэглэгч нэмэх", user, user_create_page(all_departments))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        email = (form.get("email") or "").strip().lower()
        display_name = (form.get("display_name") or "").strip()
        dept_id = form.get("department_id") or None
        new_role = form.get("role") or ROLE_USER
        if new_role not in (ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN):
            new_role = ROLE_USER
        is_admin = 1 if new_role in (ROLE_ADMIN, ROLE_SUPERADMIN) else 0
        if not email or "@" not in email:
            page = render_page("Хэрэглэгч нэмэх", user, user_create_page(all_departments, error="Зөв и-мэйл хаяг оруулна уу.", values=form))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        existing = conn.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
        if existing:
            page = render_page("Хэрэглэгч нэмэх", user, user_create_page(all_departments, error="Тэрхүү и-мэйл хаягтай хэрэглэгч аль хэдийн байна.", values=form))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        if dept_id:
            dept_row = conn.execute("SELECT id FROM departments WHERE id = ?", (dept_id,)).fetchone()
            dept_id = dept_row["id"] if dept_row else None
        timestamp = now_utc().isoformat()
        username = email
        conn.execute(
            "INSERT INTO users(username, email, display_name, password_hash, department_id, is_admin, role, is_active, created_at, must_change_password) VALUES (?, ?, ?, '', ?, ?, ?, 1, ?, 0)",
            (username, email, display_name, dept_id, is_admin, new_role, timestamp),
        )
        new_user_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        if dept_id and new_role == ROLE_USER:
            conn.execute(
                "INSERT OR IGNORE INTO user_department_permissions(user_id, department_id, can_read, can_update, created_at, updated_at) VALUES (?, ?, 1, 1, ?, ?)",
                (new_user_id, dept_id, timestamp, timestamp),
            )
        record_audit(conn, user["id"], "create", "user", entity_id=new_user_id, target_user_id=new_user_id, details=f"{email} хэрэглэгч үүслээ.")
        conn.execute("UPDATE users SET last_invited_at = ? WHERE id = ?", (timestamp, new_user_id))
        send_invitation_email(conn, new_user_id, email, display_name)
        conn.commit()
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{email} хэрэглэгч үүсгэж урилга илгээлээ."))

    if path.startswith("/users/") and path.endswith("/edit"):
        if not can_manage_users(user):
            conn.close()
            return forbidden(start_response)
        target_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, target_id)
        if not target_user:
            conn.close()
            return not_found(start_response)
        all_departments = list(conn.execute("SELECT * FROM departments ORDER BY name"))
        dept_perms = get_user_dept_perms(conn, target_user["id"])
        label = target_user["display_name"] or target_user["email"] or target_user["username"]
        if method == "GET":
            page = render_page(f"{label} — Засах", user, user_edit_page(conn, target_user, all_departments, dept_perms))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        email = (form.get("email") or "").strip().lower()
        display_name = (form.get("display_name") or "").strip()
        dept_id = form.get("department_id") or None
        new_role = form.get("role") or ROLE_USER
        if new_role not in (ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN):
            new_role = ROLE_USER
        is_admin = 1 if new_role in (ROLE_ADMIN, ROLE_SUPERADMIN) else 0
        is_active = 1 if form.get("is_active") == "1" else 0
        if not email or "@" not in email:
            page = render_page(f"{label} — Засах", user, user_edit_page(conn, target_user, all_departments, dept_perms, error="Зөв и-мэйл хаяг оруулна уу."))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        clash = conn.execute("SELECT id FROM users WHERE lower(email) = ? AND id != ?", (email, target_user["id"])).fetchone()
        if clash:
            page = render_page(f"{label} — Засах", user, user_edit_page(conn, target_user, all_departments, dept_perms, error="Тэрхүү и-мэйл хаягтай хэрэглэгч аль хэдийн байна."))
            conn.close()
            return response(start_response, "400 Bad Request", page)
        if dept_id:
            dept_row = conn.execute("SELECT id FROM departments WHERE id = ?", (dept_id,)).fetchone()
            dept_id = dept_row["id"] if dept_row else None
        if target_user["id"] == user["id"]:
            new_role = user_role(user)
            is_admin = 1 if new_role in (ROLE_ADMIN, ROLE_SUPERADMIN) else 0
            is_active = 1
        timestamp = now_utc().isoformat()
        conn.execute(
            "UPDATE users SET email = ?, display_name = ?, username = ?, department_id = ?, is_admin = ?, role = ?, is_active = ? WHERE id = ?",
            (email, display_name, email, dept_id, is_admin, new_role, is_active, target_user["id"]),
        )
        new_perms = {}
        for d in all_departments:
            new_perms[d["id"]] = {
                "can_read": form.get(f"read_{d['id']}") == "1",
                "can_update": form.get(f"update_{d['id']}") == "1",
            }
        save_user_dept_perms(conn, target_user["id"], new_perms)
        record_audit(conn, user["id"], "update", "user", entity_id=target_user["id"], target_user_id=target_user["id"], details=f"{email} хэрэглэгчийн мэдээлэл шинэчлэгдлээ.")
        conn.commit()
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{email} хэрэглэгчийн мэдээлэл шинэчлэгдлээ."))

    if path == "/kpi":
        if not is_admin_or_above(user):
            conn.close()
            return forbidden(start_response)
        page = kpi_list_page(conn, user, notice=qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path == "/kpi/create" and method == "POST":
        if not is_admin_or_above(user):
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
        if not is_admin_or_above(user):
            conn.close()
            return forbidden(start_response)
        if path.endswith("/delete") and method == "POST":
            if not is_superadmin(user):
                conn.close()
                return forbidden(start_response)
            conn.execute("DELETE FROM kpi_directories WHERE id = ?", (directory["id"],))
            record_audit(conn, user["id"], "delete", "kpi_directory", details=f"{directory['name']} KPI лавлах устгагдлаа.")
            conn.commit()
            conn.close()
            return redirect(start_response, "/kpi?notice=" + quote(f"{directory['name']} лавлах устгагдлаа."))
        page = kpi_directory_page(conn, user, directory, notice=qs_value(query, "notice"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path.startswith("/kpi/") and path.endswith("/rows/new") and method == "POST":
        if not is_admin_or_above(user):
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
        if not is_admin_or_above(user):
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
        if not is_admin_or_above(user):
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

    if path.startswith("/users/") and path.endswith("/invite") and method == "POST":
        if not can_manage_users(user):
            conn.close()
            return forbidden(start_response)
        target_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, target_id)
        if not target_user or not target_user["email"]:
            conn.close()
            return not_found(start_response)
        last_inv = target_user["last_invited_at"]
        if last_inv and (now_utc() - _parse_dt(last_inv)).total_seconds() < 600:
            conn.close()
            return redirect(start_response, "/users?notice=" + quote("Урилга илгэгдсэнээс 10 минут өнгөрөөгүй байна."))
        conn.execute("UPDATE users SET last_invited_at = ? WHERE id = ?", (now_utc().isoformat(), target_user["id"]))
        record_audit(conn, user["id"], "invite", "user", entity_id=target_user["id"], target_user_id=target_user["id"], details=f"{target_user['email']} хаягт урилга илгээлээ.")
        send_invitation_email(conn, target_user["id"], target_user["email"], target_user["display_name"] or "")
        conn.commit()
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{target_user['email']} хаягт урилга илгээлээ."))

    if path.startswith("/users/") and path.endswith("/send-otp") and method == "POST":
        if not can_manage_users(user):
            conn.close()
            return forbidden(start_response)
        target_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, target_id)
        if not target_user or not target_user["email"] or not target_user["is_active"]:
            conn.close()
            return not_found(start_response)
        otp = create_otp(conn, target_user["id"])
        record_audit(conn, user["id"], "invite", "user", entity_id=target_user["id"], target_user_id=target_user["id"], details=f"{target_user['email']} хаягт OTP илгээлээ.")
        conn.commit()
        send_otp_email(target_user["email"], target_user["display_name"] or target_user["username"], otp)
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{target_user['email']} хаягт нууц үг сэргээх OTP илгээлээ."))

    if path.startswith("/users/") and path.endswith("/delete") and method == "POST":
        if not can_manage_users(user):
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
        record_audit(conn, user["id"], "delete", "user", entity_id=target_user["id"], target_user_id=target_user["id"], details=f"{target_user['username']} хэрэглэгч устгагдлаа.")
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_user["id"],))
        conn.execute("DELETE FROM users WHERE id = ?", (target_user["id"],))
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
                    retention_period, confidentiality, integrity_impact,
                    availability_impact, asset_value, asset_category, review_frequency, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    department["id"], values["asset_name"], values["description"], values["asset_type"], values["asset_group_code"],
                    values["has_personal_data"], values["has_sensitive_data"], values["owner"], values["custodian"], values["location"],
                    values["retention_period"], values["confidentiality"], values["integrity_impact"], values["availability_impact"],
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

    def _wsgi_app(environ, start_response):
        try:
            return app(environ, start_response)
        except Exception:
            import traceback
            traceback.print_exc()
            body = error_500_page().encode("utf-8")
            start_response("500 Internal Server Error", [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(body))),
            ])
            return [body]

    with make_server(HOST, PORT, _wsgi_app) as server:
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
