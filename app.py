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
import time
import traceback
import uuid
import zlib
from zoneinfo import ZoneInfo
from decimal import ROUND_HALF_UP, Decimal
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse
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


MULTIPART_MAX_BYTES = 256 * 1024 * 1024


def _read_request_body(environ, limit=MULTIPART_MAX_BYTES):
    """Read the whole request body. Under uvicorn + a2wsgi, wsgi.input.read(n) may return fewer than n bytes while
    the body is still streaming in, so keep reading until Content-Length (or EOF when there is none) is reached."""
    stream = environ["wsgi.input"]
    try:
        remaining = int(environ.get("CONTENT_LENGTH") or 0) or None
    except ValueError:
        remaining = None
    chunks, total = [], 0
    while total < limit:
        want = min(65536, limit - total) if remaining is None else min(65536, remaining - total, limit - total)
        if want <= 0:
            break
        chunk = stream.read(want)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def parse_multipart(environ):
    # cgi.FieldStorage assumes read(n) returns n bytes; buffer the body first so streamed (chunked) uploads parse fully.
    body = _read_request_body(environ)
    env = {
        "REQUEST_METHOD": environ.get("REQUEST_METHOD", "POST"),
        "CONTENT_TYPE": environ.get("CONTENT_TYPE", ""),
        "CONTENT_LENGTH": str(len(body)),
    }
    return cgi.FieldStorage(fp=io.BytesIO(body), environ=env, keep_blank_values=True)


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
    ensure_vulnerabilities_table(conn)
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
    ensure_column(conn, "users", "is_it_head", "INTEGER NOT NULL DEFAULT 0")
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

    # "Бүртгэл" (Registry) dropdown — sits right after "Аудит", same structure as "Бичиг баримт"
    # Vulnerability register: shown only to roles granted access in VulnReg → Settings (checked again server-side).
    vuln_href = ""
    _vc = conn if conn else get_db()
    try:
        ensure_vulnerabilities_table(_vc)
        _vu = vuln_user(_vc, user)
        if vuln_perm(_vu, "access"):
            vuln_href = "/registry/vulnerabilities/dashboard" if vuln_perm(_vu, "dashboard") else "/registry/vulnerabilities"
    except Exception:
        vuln_href = ""
    finally:
        if conn is None:
            _vc.close()
    # Shown to anyone with Incident Register access (Superadmin, InfoSec, Recipient, CTO) or VulnReg access.
    _ic = conn if conn else get_db()
    try:
        incident_view = incident_access(_ic, user)[0]
    except Exception:
        incident_view = False
    finally:
        if conn is None:
            _ic.close()
    if incident_view or vuln_href:
        links_html += (
            '<li class="nav-dropdown">'
            '<a class="nav-dropdown-trigger" href="#">Бүртгэл ▾</a>'
            '<ul class="nav-dropdown-menu">'
            + ('<li><a class="dropdown-item" href="/incidents/">Зөрчлийн бүртгэл</a></li>' if incident_view else '')
            + (f'<li><a class="dropdown-item" href="{vuln_href}">Эмзэг байдлын бүртгэл</a></li>' if vuln_href else '')
            + '</ul>'
            '</li>'
        )

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
        <a class="button-link ghost nav-guide" href="/guide" title="Хэрэглэгчийн гарын авлага">? Гарын авлага</a>
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


GUIDE_TEMPLATE = BASE_DIR / "templates" / "guide.html"
GUIDE_ROLE_LABELS = {"superadmin": "Супер админ", "admin": "Хэлтсийн админ", "user": "Хэрэглэгч",
                     "infosec": "InfoSec", "receiver": "Хүлээн авагч", "engineer": "Инженер", "cto": "CTO"}


def guide_page(conn, user):
    """User guide. Static content from templates/guide.html; sections carry data-roles so the page can mark
    which ones apply to the viewer (nothing is hidden — everyone may read the whole guide)."""
    role = user_role(user)
    roles = [role]
    try:
        ensure_vulnerabilities_table(conn)
        vu = vuln_user(conn, user)
        roles += sorted(_vroles(vu))
        if vuln_perm(vu, "access"):
            roles.append("vuln_access")
        if incident_access(conn, user)[0]:
            roles.append("incident_view")
    except Exception:
        pass
    me = ", ".join(GUIDE_ROLE_LABELS[r] for r in roles if r in GUIDE_ROLE_LABELS)
    body = (GUIDE_TEMPLATE.read_text(encoding="utf-8")
            .replace("{{ME_ROLES_JSON}}", json.dumps(roles))
            .replace("{{ME_ROLES_TEXT}}", html.escape(me)))
    return render_page("Хэрэглэгчийн гарын авлага", user, body, conn=conn)


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
    ensure_vulnerabilities_table(conn)  # users.vuln_role
    user_rows = conn.execute(
        """
        SELECT users.id, users.username, users.email, users.display_name,
               users.is_admin, users.role, users.vuln_role, users.is_active, users.last_login_at,
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
        role = html.escape(_role_labels.get(role_val, role_val))
        if vuln_roles_of(row):
            role += f'<br><span class="muted" style="font-size:.85em">{html.escape(vuln_roles_text(vuln_roles_of(row)))}</span>'
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


_SYS_ROLE_CHOICES = ((ROLE_USER, "Хэрэглэгч"), (ROLE_ADMIN, "Админ"), (ROLE_SUPERADMIN, "Супер Админ"))


def role_level_from_form(form):
    """(system role, [vuln roles]) from the «Эрхийн түвшин» checkboxes."""
    sys_role = form.get("role") or ROLE_USER
    if sys_role not in dict(_SYS_ROLE_CHOICES):
        sys_role = ROLE_USER
    return sys_role, [r for r in VULN_ROLES if form.get(f"vuln_role_{r}") == "1"]


def log_role_change(conn, actor, target, old_sys, new_sys, old_v, new_v, reason):
    """Audit (who / when / previous / new / reason) for role changes made on the Users page."""
    labels = dict(_SYS_ROLE_CHOICES)
    name = _vuln_user_label(target)
    if old_sys != new_sys:
        _vuln_config_log(conn, actor, f"user_sysrole:{target['id']}", f"Системийн эрх — {name}",
                         labels.get(old_sys, old_sys or "—"), labels.get(new_sys, new_sys), reason)
    if old_v != new_v:
        _vuln_config_log(conn, actor, f"user_role:{target['id']}", f"Эрх — {name}",
                         vuln_roles_text(old_v), vuln_roles_text(new_v), reason)


_UC_ICON = {
    "user": '<path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"/><path d="M4 20a8 8 0 0 1 16 0"/>',
    "admin": '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/>',
    "superadmin": '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/>',
    "infosec": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    "engineer": '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4 2.5-2.5z"/>',
    "cto": '<path d="M12 2l2.9 6.3 6.9.7-5.2 4.6 1.5 6.8L12 17l-6.1 3.4 1.5-6.8L2.2 9l6.9-.7L12 2z"/>',
    "receiver": '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.1L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z"/>',
}


def _uc_icon(key):
    return (f'<svg class="uc-role-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
            f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{_UC_ICON.get(key, "")}</svg>')


_SYS_ROLE_ICON_KEY = {ROLE_USER: "user", ROLE_ADMIN: "admin", ROLE_SUPERADMIN: "superadmin"}

_USER_CREATE_CSS = """
<style>
.uc-panel { max-width: 640px; margin: 0 auto; padding: 28px; }
.uc-panel h1 { margin-bottom: 4px; }
.uc-form { display: flex; flex-direction: column; gap: 22px; margin-top: 18px; }
.uc-section { border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--surface); margin: 0; padding: 0; min-width: 0; }
.uc-sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.uc-field textarea { width: 100%; min-height: 64px; }
.uc-section .table-wrap { margin: 0; }
.uc-section table { width: 100%; }
.uc-section-head { padding: 10px 16px; border-bottom: 1px solid var(--border); background: var(--surface-alt);
  border-radius: var(--radius-md) var(--radius-md) 0 0; display: flex; align-items: baseline; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
.uc-section-title { font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; color: var(--text-secondary); }
.uc-section-hint { font-size: 0.75rem; color: var(--muted); }
.uc-section-body { padding: 16px; display: flex; flex-direction: column; gap: 14px; }
.uc-field { display: flex; flex-direction: column; gap: 6px; font-weight: 500; color: var(--text-secondary); }
.uc-field input, .uc-field select { height: 40px; width: 100%; }
.uc-field .uc-opt { font-weight: 400; color: var(--muted); }
.uc-roles { display: grid; gap: 10px; }
.uc-roles-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.uc-roles-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.uc-role { position: relative; display: flex; align-items: center; gap: 10px; min-height: 52px; padding: 10px 12px;
  border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--surface-alt); cursor: pointer;
  font-weight: 500; color: var(--text-secondary); line-height: 1.3;
  transition: border-color .15s, background .15s, box-shadow .15s; }
.uc-role:hover { border-color: var(--border-strong); }
.uc-role-inline { align-self: flex-start; min-height: 0; padding: 8px 14px; }
.uc-role input { flex: none; width: 16px; height: 16px; margin: 0; accent-color: var(--primary); cursor: pointer; }
.uc-role-icon { flex: none; color: var(--muted); transition: color .15s; }
.uc-role-name { flex: 1; min-width: 0; }
.uc-role:has(input:checked) { border-color: var(--primary); background: var(--primary-light); color: var(--text);
  box-shadow: 0 0 0 1px var(--primary) inset; }
.uc-role:has(input:checked) .uc-role-icon { color: var(--primary); }
.uc-role:has(input:focus-visible) { outline: 2px solid var(--primary); outline-offset: 2px; }
.uc-role:has(input:disabled) { opacity: .6; cursor: not-allowed; }
.uc-info { display: flex; gap: 10px; align-items: flex-start; padding: 10px 14px; border-radius: var(--radius-md);
  background: var(--primary-light); border: 1px solid var(--primary-border); color: var(--text-secondary); font-size: 0.8125rem; }
.uc-info svg { flex: none; margin-top: 2px; color: var(--primary); }
.uc-actions { display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 18px; }
.uc-actions > * { min-width: 110px; justify-content: center; text-align: center; }
@media (max-width: 640px) {
  .uc-panel { padding: 18px 16px; }
  .uc-roles-3 { grid-template-columns: 1fr; }
  .uc-roles-2 { grid-template-columns: 1fr; }
  .uc-section-body { padding: 14px; }
  .uc-actions { flex-direction: column-reverse; }
  .uc-actions > * { width: 100%; }
}
@media (min-width: 641px) and (max-width: 760px) {
  .uc-roles-3 { grid-template-columns: 1fr; }
}
</style>
"""


def _uc_role_sections(sel_sys, sel_vuln, lock_sys=False):
    """«Системийн эрх» (one "role" radio) + «Эмзэг байдлын бүртгэл» (vuln_role_<r>=1 checkboxes) as card sections."""
    sel_sys = sel_sys if sel_sys in dict(_SYS_ROLE_CHOICES) else ROLE_USER
    dis = " disabled" if lock_sys else ""
    sys_cards = "".join(
        f'<label class="uc-role"><input type="radio" name="role" value="{r}"{" checked" if r == sel_sys else ""}{dis}>'
        f'{_uc_icon(_SYS_ROLE_ICON_KEY[r])}<span class="uc-role-name">{lbl}</span></label>'
        for r, lbl in _SYS_ROLE_CHOICES)
    vuln_cards = "".join(
        f'<label class="uc-role"><input type="checkbox" name="vuln_role_{r}" value="1"{" checked" if r in sel_vuln else ""}>'
        f'{_uc_icon(r)}<span class="uc-role-name">{html.escape(VULN_ROLE_LABELS[r])}</span></label>'
        for r in VULN_ROLES)
    lock_note = '<p class="muted" style="margin:0;font-size:.8125rem">Өөрийн системийн түвшинг өөрчлөх боломжгүй.</p>' if lock_sys else ""
    return f"""
        <fieldset class="uc-section">
          <legend class="uc-sr">Системийн эрх</legend>
          <div class="uc-section-head"><span class="uc-section-title">Системийн эрх</span><span class="uc-section-hint">нэгийг сонгоно</span></div>
          <div class="uc-section-body"><div class="uc-roles uc-roles-3">{sys_cards}</div>{lock_note}</div>
        </fieldset>
        <fieldset class="uc-section">
          <legend class="uc-sr">Эмзэг байдлын бүртгэл</legend>
          <div class="uc-section-head"><span class="uc-section-title">Эмзэг байдлын бүртгэл</span><span class="uc-section-hint">хэдийг ч сонгож болно</span></div>
          <div class="uc-section-body"><div class="uc-roles uc-roles-2">{vuln_cards}</div></div>
        </fieldset>"""


def user_create_page(departments, error="", values=None):
    values = values or {}
    dept_options = '<option value="">— Хэлтэс сонгоогүй —</option>'
    for d in departments:
        sel = 'selected' if str(values.get("department_id", "")) == str(d["id"]) else ""
        dept_options += f'<option value="{d["id"]}" {sel}>{html.escape(d["name"])}</option>'
    sel_sys, sel_vuln = role_level_from_form(values)
    role_sections = _uc_role_sections(sel_sys, sel_vuln)
    info_icon = ('<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" '
                 'stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>')
    body = f"""
    {_USER_CREATE_CSS}
    <section class="panel uc-panel">
      <h1>Шинэ хэрэглэгч нэмэх</h1>
      {fmt_error(error)}
      <form method="post" action="/users/create" class="uc-form">
        <div class="uc-section">
          <div class="uc-section-head"><span class="uc-section-title">Хэрэглэгчийн мэдээлэл</span></div>
          <div class="uc-section-body">
            <label class="uc-field">Azure и-мэйл хаяг<input type="email" name="email" value="{html.escape(values.get('email', ''))}" required autofocus placeholder="user@company.com"></label>
            <label class="uc-field">Дэлгэцийн нэр (заавал биш)<input type="text" name="display_name" value="{html.escape(values.get('display_name', ''))}" placeholder="Нэр Овог"></label>
            <label class="uc-field">Үндсэн хэлтэс
              <select name="department_id">{dept_options}</select>
            </label>
          </div>
        </div>
        {role_sections}
        <div class="uc-info">{info_icon}<span>Хэрэглэгч порталаар нэвтэрч орно. Нууц үг шаардлагагүй.</span></div>
        <div class="uc-actions">
          <a class="button-link ghost" href="/users">Буцах</a>
          <button type="submit">Үүсгэх</button>
        </div>
      </form>
    </section>
    """
    return body


def user_edit_page(conn, target_user, departments, dept_perms, error="", values=None, lock_sys=False):
    # Normalise target_user to dict so .get() works everywhere below
    tu = dict(target_user) if not isinstance(target_user, dict) else target_user
    values = values or tu
    dept_options = '<option value="">— Хэлтэс сонгоогүй —</option>'
    selected_dept = str(values.get("department_id") or tu.get("department_id") or "")
    for d in departments:
        sel = 'selected' if str(d["id"]) == selected_dept else ""
        dept_options += f'<option value="{d["id"]}" {sel}>{html.escape(d["name"])}</option>'
    cur_role = tu.get("role") or (ROLE_ADMIN if tu.get("is_admin") else ROLE_USER)
    role_sections = _uc_role_sections(cur_role, vuln_roles_of(tu), lock_sys=bool(lock_sys))
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
    {_USER_CREATE_CSS}
    <section class="panel uc-panel">
      <h1>{html.escape(tu.get('display_name') or tu.get('email') or tu.get('username',''))} — Засах</h1>
      {fmt_error(error)}
      <form method="post" action="/users/{target_user['id']}/edit" class="uc-form">
        <div class="uc-section">
          <div class="uc-section-head"><span class="uc-section-title">Хэрэглэгчийн мэдээлэл</span></div>
          <div class="uc-section-body">
            <label class="uc-field">Azure и-мэйл хаяг<input type="email" name="email" value="{edit_email}" required></label>
            <label class="uc-field">Дэлгэцийн нэр<input type="text" name="display_name" value="{edit_display}" placeholder="Нэр Овог"></label>
            <label class="uc-field">Хэлтэс (үндсэн)
              <select name="department_id">{dept_options}</select>
            </label>
            <label class="uc-role uc-role-inline">
              <input type="checkbox" name="is_active" value="1" {is_active_checked}><span class="uc-role-name">Идэвхтэй</span>
            </label>
          </div>
        </div>
        {role_sections}
        <div class="uc-section">
          <div class="uc-section-head"><span class="uc-section-title">Хэлтсийн хандах эрх</span></div>
          <div class="uc-section-body">
            <p class="muted" style="margin:0;font-size:.8125rem">Админ болон Супер Админ эрхтэй хэрэглэгчид бүх хэлтэст автоматаар хандана.</p>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Хэлтэс</th><th style="text-align:center">Унших</th><th style="text-align:center">Засах / Нэмэх / Устгах</th></tr>
                </thead>
                <tbody>{perm_rows}</tbody>
              </table>
            </div>
          </div>
        </div>
        <div class="uc-actions">
          <a class="button-link ghost" href="/users">Буцах</a>
          <button type="submit">Хадгалах</button>
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
            if "L1-POL-12" in d.name and incident_access(conn, user)[1] else ""
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
    if is_incident_doc and incident_register and incident_access(conn, user)[0]:
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
    "vulnerability": "Эмзэг байдал",
    "vuln_setting": "Эмзэг байдлын тохиргоо",
}


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_VULN_TEXT_LIMITS = {
    "cve_id": 32, "title": 300, "source": 200, "source_url": 2000,
    "description": 10000, "scope": 5000, "verification_method": 5000, "recommendation": 10000, "threat_trend": 5000,
    "owner_custodian": 300, "affected_asset": 300,
}


def _valid_iso_date(value):
    if not _ISO_DATE_RE.match(value):
        return False
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


_VULN_TABLE_DDL = """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            source_url TEXT NOT NULL DEFAULT '',
            published_date TEXT NOT NULL DEFAULT '',
            reported_date TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT '',
            verification_method TEXT NOT NULL DEFAULT '',
            recommendation TEXT NOT NULL DEFAULT '',
            threat_trend TEXT NOT NULL DEFAULT '',
            cvss_score REAL,
            severity TEXT NOT NULL DEFAULT '',
            remediation_days INTEGER,
            due_date TEXT NOT NULL DEFAULT '',
            department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
"""


_VULN_EXTRA_DDL = """
        CREATE TABLE IF NOT EXISTS vulnerability_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
            actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            actor_name TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            field TEXT NOT NULL DEFAULT '',
            old_value TEXT NOT NULL DEFAULT '',
            new_value TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_vuln_activity_vuln ON vulnerability_activity(vulnerability_id, id);
        -- The activity log is an audit trail: rows can be appended, never edited or removed.
        CREATE TRIGGER IF NOT EXISTS trg_vuln_activity_no_update BEFORE UPDATE ON vulnerability_activity
        BEGIN SELECT RAISE(ABORT, 'vulnerability_activity is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS trg_vuln_activity_no_delete BEFORE DELETE ON vulnerability_activity
        BEGIN SELECT RAISE(ABORT, 'vulnerability_activity is append-only'); END;
        CREATE TABLE IF NOT EXISTS vulnerability_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            size INTEGER NOT NULL DEFAULT 0,
            uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            uploaded_at TEXT NOT NULL,
            deleted_at TEXT NOT NULL DEFAULT '',
            deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_vuln_files_vuln ON vulnerability_files(vulnerability_id);
"""
_VULN_EXTRA_COLUMNS = (
    ("status", "TEXT NOT NULL DEFAULT 'new'"),
    # Responsible person chosen at registration: acts as the Recipient for this record (review, return, assign engineer).
    ("reviewer_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("vuln_custom", "TEXT NOT NULL DEFAULT '{}'"),
    ("asset_id", "INTEGER REFERENCES assets(id) ON DELETE SET NULL"),
    ("assignee_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("impact", "TEXT NOT NULL DEFAULT ''"),
    ("risk_justification", "TEXT NOT NULL DEFAULT ''"),
    ("remediation_notes", "TEXT NOT NULL DEFAULT ''"),
    ("remediated_date", "TEXT NOT NULL DEFAULT ''"),
    ("closed_at", "TEXT NOT NULL DEFAULT ''"),
    ("risk_accept_reason", "TEXT NOT NULL DEFAULT ''"),
    ("risk_accept_approver_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("risk_accept_until", "TEXT NOT NULL DEFAULT ''"),
    ("updated_by", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("deleted_at", "TEXT NOT NULL DEFAULT ''"),
    ("deleted_by", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("owner_custodian", "TEXT NOT NULL DEFAULT ''"),
    ("in_use", "TEXT NOT NULL DEFAULT ''"),
    # Affected asset / system as free text (form section 2). Older records link to assets via asset_id instead.
    ("affected_asset", "TEXT NOT NULL DEFAULT ''"),
    # Registration form section 2 (informational only; no workflow effect).
    ("env_present", "TEXT NOT NULL DEFAULT ''"),
    ("compromise_signs", "TEXT NOT NULL DEFAULT ''"),
    # Step 4a — InfoSec decides whether the asset is affected (after the engineer submits section 2 + assessment).
    ("ia_note", "TEXT NOT NULL DEFAULT ''"),
    ("ia_decided_by", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("ia_decided_at", "TEXT NOT NULL DEFAULT ''"),
    # Registration batch: one record (finding) per affected asset, all sharing the first record's id.
    ("group_id", "INTEGER"),
    # Step 3 — Engineer assessment
    ("as_scope", "TEXT NOT NULL DEFAULT ''"),
    ("as_system_owner", "TEXT NOT NULL DEFAULT ''"),
    ("as_version", "TEXT NOT NULL DEFAULT ''"),
    ("as_internet_facing", "TEXT NOT NULL DEFAULT ''"),
    ("as_test_method", "TEXT NOT NULL DEFAULT ''"),
    ("as_evidence", "TEXT NOT NULL DEFAULT ''"),
    ("as_patch_available", "TEXT NOT NULL DEFAULT ''"),
    ("as_business_impact", "TEXT NOT NULL DEFAULT ''"),
    ("as_conclusion", "TEXT NOT NULL DEFAULT ''"),
    ("as_affected", "TEXT NOT NULL DEFAULT ''"),
    ("as_exploited", "TEXT NOT NULL DEFAULT ''"),
    ("as_incident_ref", "TEXT NOT NULL DEFAULT ''"),
    ("as_submitted_at", "TEXT NOT NULL DEFAULT ''"),
    # Step 4 — InfoSec risk assessment (MAS-14)
    ("ra_threat", "TEXT NOT NULL DEFAULT ''"),
    ("ra_impacts", "TEXT NOT NULL DEFAULT ''"),
    ("ra_impact", "INTEGER"),
    ("ra_likelihood", "INTEGER"),
    ("ra_score", "INTEGER"),
    ("ra_level", "TEXT NOT NULL DEFAULT ''"),
    ("ra_due", "TEXT NOT NULL DEFAULT ''"),
    ("ra_decision", "TEXT NOT NULL DEFAULT ''"),
    ("ra_decision_note", "TEXT NOT NULL DEFAULT ''"),
    ("ra_assessed_by", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    ("ra_assessed_at", "TEXT NOT NULL DEFAULT ''"),
    ("risk_accept_requested_by", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
    # Step 5 — Remediation / temporary mitigation
    ("rm_plan", "TEXT NOT NULL DEFAULT ''"),
    ("rm_actions", "TEXT NOT NULL DEFAULT ''"),
    ("rm_target_date", "TEXT NOT NULL DEFAULT ''"),
    ("rm_change_ref", "TEXT NOT NULL DEFAULT ''"),
    ("rm_fix_type", "TEXT NOT NULL DEFAULT ''"),
    ("tm_controls", "TEXT NOT NULL DEFAULT ''"),
    ("tm_until", "TEXT NOT NULL DEFAULT ''"),
    ("avoid_note", "TEXT NOT NULL DEFAULT ''"),
    ("avoid_confirmed_at", "TEXT NOT NULL DEFAULT ''"),
    # Steps 6–7 — Verification and closure
    ("vf_note", "TEXT NOT NULL DEFAULT ''"),
    ("closure_comment", "TEXT NOT NULL DEFAULT ''"),
    ("residual_risk", "TEXT NOT NULL DEFAULT ''"),
    ("risk_status", "TEXT NOT NULL DEFAULT ''"),
)
_VULN_SETTINGS_DDL = """
        CREATE TABLE IF NOT EXISTS vuln_substitutes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            principal_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            substitute_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT NOT NULL DEFAULT '',
            revoked_by INTEGER REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_vuln_subst_sub ON vuln_substitutes(substitute_id, start_date, end_date);
        -- Configuration audit log: who / when / previous value / new value / reason. Append-only.
        CREATE TABLE IF NOT EXISTS vuln_config_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            actor_name TEXT NOT NULL DEFAULT '',
            setting TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            old_value TEXT NOT NULL DEFAULT '',
            new_value TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS trg_vuln_config_audit_no_update BEFORE UPDATE ON vuln_config_audit
        BEGIN SELECT RAISE(ABORT, 'vuln_config_audit is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS trg_vuln_config_audit_no_delete BEFORE DELETE ON vuln_config_audit
        BEGIN SELECT RAISE(ABORT, 'vuln_config_audit is append-only'); END;
"""
# Statuses of the earlier workflow and their equivalent in the current one (migrated once).
_VULN_LEGACY_STATUS = {"in_progress": "remediation", "on_hold": "assigned", "risk_accepted": "accepted", "reopened": "remediation",
                       "impact_review": "risk_assessment"}  # the separate impact step is now part of the risk assessment
_vuln_schema_ready = False


def _vuln_migrate_it_head_to_receiver(conn):
    """The «IT-ийн дарга (IT Head)» role was replaced by «Хүлээн авагч» (receiver) with identical duties.

    Idempotent: moves user roles, substitutions and stored access permissions from the old key to the new one.
    """
    for row in conn.execute("SELECT id, vuln_role FROM users WHERE (',' || vuln_role || ',') LIKE '%,it_head,%'").fetchall():
        got = {r.strip() for r in (row["vuln_role"] or "").split(",")} - {"it_head", ""}
        got.add("receiver")
        conn.execute("UPDATE users SET vuln_role = ?, is_it_head = 1 WHERE id = ?", (vuln_roles_value(got), row["id"]))
    conn.execute("UPDATE vuln_substitutes SET role = 'receiver' WHERE role = 'it_head'")
    raw = get_setting(conn, VULN_PERMS_SETTING, "")
    if raw:
        try:
            stored = json.loads(raw)
        except ValueError:
            stored = None
        if isinstance(stored, dict) and "it_head" in stored:
            stored["receiver"] = stored.pop("it_head")
            set_setting(conn, VULN_PERMS_SETTING, json.dumps(stored))


def ensure_vulnerabilities_table(conn):
    global _vuln_schema_ready
    if _vuln_schema_ready:
        return
    conn.execute(_VULN_TABLE_DDL)
    ensure_column(conn, "users", "is_it_head", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "vulnerabilities", "threat_trend", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "vulnerabilities", "severity", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "vulnerabilities", "remediation_days", "INTEGER")
    ensure_column(conn, "vulnerabilities", "due_date", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "users", "vuln_role", "TEXT NOT NULL DEFAULT ''")
    # One-time carry-over of the old Recipient checkbox into the VulnReg role (now «Хүлээн авагч»).
    conn.execute("UPDATE users SET vuln_role = 'receiver' WHERE is_it_head = 1 AND vuln_role = ''")
    for column, definition in _VULN_EXTRA_COLUMNS:
        ensure_column(conn, "vulnerabilities", column, definition)
    conn.executescript(_VULN_EXTRA_DDL)
    conn.executescript(_VULN_SETTINGS_DDL)
    _vuln_migrate_it_head_to_receiver(conn)
    ensure_column(conn, "vulnerability_files", "category", "TEXT NOT NULL DEFAULT ''")
    for old, new in _VULN_LEGACY_STATUS.items():
        conn.execute("UPDATE vulnerabilities SET status = ? WHERE status = ?", (new, old))
    conn.execute("UPDATE vulnerabilities SET group_id = id WHERE group_id IS NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_assignee ON vulnerabilities(assignee_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_department ON vulnerabilities(department_id)")
    conn.commit()
    _vuln_schema_ready = True


# SLA policy: lowest CVSS score of each severity band + remediation days. Stored as JSON in
# app_settings[vuln_sla] and edited on /registry/vulnerabilities/settings; these are the defaults.
# The Low band always starts just above 0.0 (CVSS 0.0 = "None", no deadline).
VULN_SLA_SETTING = "vuln_sla"
VULN_SLA_LEVELS = ("critical", "high", "medium", "low")
VULN_SLA_DEFAULT = {
    "critical": {"min": 9.0, "days": 5},
    "high": {"min": 7.0, "days": 30},
    "medium": {"min": 4.0, "days": 60},
    "low": {"min": 0.1, "days": 90},
}
VULN_SLA_MAX_DAYS = 365


def _vuln_sla_errors(sla):
    """Validate an SLA dict; returns {form field: message} (empty when valid)."""
    errors = {}
    for level in VULN_SLA_LEVELS:
        band = sla.get(level) if isinstance(sla, dict) else None
        if not isinstance(band, dict):
            errors[f"{level}_days"] = "Утга дутуу байна."
            continue
        days = band.get("days")
        if not isinstance(days, int) or isinstance(days, bool) or not (1 <= days <= VULN_SLA_MAX_DAYS):
            errors[f"{level}_days"] = f"1–{VULN_SLA_MAX_DAYS} хоорондох бүхэл тоо оруулна уу."
        if level != "low":
            m = band.get("min")
            if not isinstance(m, (int, float)) or isinstance(m, bool) or not (0.1 <= m <= 10.0):
                errors[f"{level}_min"] = "0.1–10.0 хооронд байх ёстой."
    if errors:
        return errors
    if not sla["critical"]["min"] > sla["high"]["min"]:
        errors["high_min"] = "High-ийн доод хязгаар Critical-аас бага байх ёстой."
    if not sla["high"]["min"] > sla["medium"]["min"]:
        errors["medium_min"] = "Medium-ийн доод хязгаар High-аас бага байх ёстой."
    if not sla["medium"]["min"] > 0.1:
        errors["medium_min"] = "Medium-ийн доод хязгаар 0.1-ээс их байх ёстой."
    return errors


def vuln_sla(conn):
    """Current SLA policy (falls back to the defaults if the stored value is missing or invalid)."""
    raw = get_setting(conn, VULN_SLA_SETTING, "")
    if raw:
        try:
            sla = json.loads(raw)
            if not _vuln_sla_errors(sla):
                return {lvl: {"min": float(sla[lvl]["min"]) if lvl != "low" else 0.1, "days": int(sla[lvl]["days"])}
                        for lvl in VULN_SLA_LEVELS}
        except (ValueError, TypeError, KeyError):
            pass
    return json.loads(json.dumps(VULN_SLA_DEFAULT))


def cvss_severity(score, sla=None):
    """Map a CVSS score to (severity, remediation_days). days is None when there is no deadline."""
    if score is None:
        return "", None
    sla = sla or VULN_SLA_DEFAULT
    for level in VULN_SLA_LEVELS:
        if score >= sla[level]["min"] - 1e-9:
            return level.capitalize(), sla[level]["days"]
    return "None", None


_VULN_EXTRA_TEXT_LIMITS = {"impact": 5000, "risk_justification": 5000, "remediation_notes": 10000}
VULN_STATUS_LABELS = {
    "new": "Шинэ",
    "returned": "Буцаасан",
    "assigned": "Хариуцагч томилсон",
    "under_assessment": "Үнэлгээ хийгдэж буй",
    "not_affected": "Нөлөөлөөгүй – Хаагдсан",
    "risk_assessment": "Эрсдэлийн үнэлгээ",
    "pending_cto": "CTO-ийн зөвшөөрөл хүлээж буй",
    "accepted": "Эрсдэл хүлээн зөвшөөрсөн",
    "transferred": "Шилжүүлсэн – Хаагдсан",
    "avoidance": "Зайлсхийх (систем зогсоох)",
    "remediation": "Засвар хийгдэж буй",
    "verification": "Баталгаажуулалт",
    "temp_mitigation": "Түр хамгаалалт",
    "closed": "Хаагдсан",
}
VULN_STATUS_ORDER = list(VULN_STATUS_LABELS)
# No remediation deadline is tracked in these statuses (the finding is closed or its risk formally accepted).
VULN_CLOSED_STATUSES = ("closed", "not_affected", "transferred", "accepted")
# Statuses in which the Recipient may (re)assign the responsible engineer.
VULN_ASSIGNABLE_STATUSES = ("new", "assigned", "under_assessment", "remediation", "avoidance", "temp_mitigation")

# Workflow actions: key -> (from statuses, actor, label). Actor: infosec | receiver | cto | assignee.
# Superadmin may act in every role. Everything is re-checked on the server in vuln_available_actions().
VULN_ACTIONS = {
    "return": (("new",), "receiver", "Буцаах (мэдээлэл дутуу)"),
    "resubmit": (("returned",), "infosec", "Дахин илгээх"),
    # The engineer fills in section 2 + assessment straight from "assigned" (no separate "start" step).
    "save_assessment": (("assigned", "under_assessment"), "assignee", "Үнэлгээ хадгалах"),
    "submit_assessment": (("assigned", "under_assessment"), "assignee", "Үнэлгээ илгээх"),
    "risk_assess": (("risk_assessment",), "infosec", "Эрсдэлийн үнэлгээ"),
    "cto_approve": (("pending_cto",), "cto", "Эрсдэл хүлээн зөвшөөрөх"),
    "cto_reject": (("pending_cto",), "cto", "Татгалзах"),
    "avoid_confirm": (("avoidance",), "assignee", "Систем зогсоосныг баталгаажуулах"),
    "avoid_close": (("avoidance",), "infosec", "Хянаж хаах"),
    "save_remediation": (("remediation",), "assignee", "Засварын төлөвлөгөө хадгалах"),
    "submit_fix": (("remediation",), "assignee", "Засвар хийсэн — шалгуулах"),
    "submit_temp": (("remediation",), "assignee", "Түр хамгаалалт хэрэгжүүлсэн"),
    "cannot_remediate": (("remediation",), "assignee", "Засварлах боломжгүй"),
    "verify_fail": (("verification",), "infosec", "Засагдаагүй — буцаах"),
    "verify_temp": (("verification",), "infosec", "Түр хамгаалалт гэж батлах"),
    "close": (("verification",), "infosec", "Баталгаажуулж хаах"),
    "temp_resume": (("temp_mitigation",), "assignee", "Засвар руу шилжүүлэх"),
}

# ── VulnReg roles, access permissions, substitutes ──────────────────────────
VULN_ROLES = ("infosec", "receiver", "engineer", "cto")
VULN_ROLE_LABELS = {"infosec": "Мэдээллийн аюулгүй байдал (InfoSec)", "receiver": "Хүлээн авагч",
                    "engineer": "Инженер", "cto": "CTO", "": "Хандах эрхгүй"}
VULN_SUBSTITUTABLE_ROLES = ("infosec", "receiver", "cto")
# users.vuln_role holds zero or more roles as a comma-separated list in VULN_ROLES order, e.g. "receiver,engineer".
_VULN_HAS_ROLE_SQL = "(',' || {col} || ',') LIKE ('%,' || ? || ',%')"


def vuln_roles_of(row):
    """The user's own VulnReg roles (list, canonical order) parsed from users.vuln_role."""
    try:
        raw = row["vuln_role"] or ""
    except (KeyError, IndexError, TypeError):
        raw = ""
    got = {r.strip() for r in raw.split(",")}
    return [r for r in VULN_ROLES if r in got]


def vuln_roles_value(roles):
    roles = set(roles)
    return ",".join(r for r in VULN_ROLES if r in roles)


def vuln_roles_text(roles):
    return ", ".join(VULN_ROLE_LABELS[r] for r in roles) or VULN_ROLE_LABELS[""]
VULN_PERMS = ("access", "view_all", "export", "dashboard")
VULN_PERM_LABELS = {"access": "Эмзэг байдлын бүртгэл рүү хандах", "view_all": "Бүх бүртгэлийг харах",
                    "export": "Экспорт (CSV/XLSX)", "dashboard": "Хяналтын самбар"}
VULN_PERMS_SETTING = "vuln_role_perms"
VULN_PERMS_DEFAULT = {
    "infosec": {"access": True, "view_all": True, "export": True, "dashboard": True},
    "receiver": {"access": True, "view_all": True, "export": True, "dashboard": True},
    "cto": {"access": True, "view_all": True, "export": True, "dashboard": True},
    "engineer": {"access": True, "view_all": False, "export": False, "dashboard": False},
}
# InfoSec runs the register and its settings, so these can never be switched off (prevents lock-out).
VULN_PERMS_LOCKED = {("infosec", "access"), ("infosec", "view_all")}


def vuln_role_perms(conn):
    perms = json.loads(json.dumps(VULN_PERMS_DEFAULT))
    raw = get_setting(conn, VULN_PERMS_SETTING, "")
    if raw:
        try:
            stored = json.loads(raw)
            for role in VULN_ROLES:
                for perm in VULN_PERMS:
                    if isinstance(stored.get(role, {}).get(perm), bool) and (role, perm) not in VULN_PERMS_LOCKED:
                        perms[role][perm] = stored[role][perm]
        except (ValueError, TypeError, AttributeError):
            pass
    return perms


def _vuln_today():
    return now_utc().date().isoformat()


def vuln_active_substitutions(conn, user_id, today=None):
    """Roles the user currently holds as a substitute (period covers today and not revoked)."""
    today = today or _vuln_today()
    return conn.execute(
        """SELECT * FROM vuln_substitutes WHERE substitute_id = ? AND revoked_at = ''
           AND start_date <= ? AND end_date >= ?""", (user_id, today, today)).fetchall()


def vuln_user(conn, user):
    """User row as a dict carrying the effective VulnReg roles (own role + active substitutions) and permissions."""
    if user is None:
        return None
    if isinstance(user, dict) and "_vroles" in user:
        return user
    u = dict(user)
    own = vuln_roles_of(u)
    roles = set(own)
    subs = vuln_active_substitutions(conn, u["id"])
    roles |= {s["role"] for s in subs if s["role"] in VULN_SUBSTITUTABLE_ROLES}
    perms = vuln_role_perms(conn)
    eff = {p: is_superadmin(u) or any(perms[r][p] for r in roles) for p in VULN_PERMS}
    u["_vrole"] = own
    u["_vroles"] = roles
    u["_vsubs"] = [{"role": s["role"], "until": s["end_date"]} for s in subs]
    # Principals this user currently stands in for: their per-record responsibilities pass to the substitute too.
    u["_vsub_for"] = sorted({s["principal_id"] for s in subs if s["role"] in VULN_SUBSTITUTABLE_ROLES})
    rids = [u["id"]] + [i for i in u["_vsub_for"] if i != u["id"]]
    u["_vreviewer"] = bool(conn.execute(
        f"SELECT 1 FROM vulnerabilities WHERE deleted_at = '' AND reviewer_id IN ({','.join('?' * len(rids))}) LIMIT 1",
        rids).fetchone())
    if u["_vreviewer"]:
        # Responsible person for some record (acts as Recipient for it): may open the register; scope limits what they see.
        eff["access"] = True
    u["_vperms"] = eff
    return u


def _vroles(user):
    try:
        return user["_vroles"]
    except (KeyError, IndexError, TypeError):
        return set()


def vuln_perm(user, perm):
    if is_superadmin(user):
        return True
    try:
        return bool(user["_vperms"][perm])
    except (KeyError, IndexError, TypeError):
        return False


INCIDENT_MANAGE_ROLES = {"infosec"}
INCIDENT_VIEW_ROLES = {"infosec", "receiver", "cto"}
INCIDENT_REGISTER_SLUG = "zorchlin-burtgel"


def incident_access(conn, user):
    """(can_view, can_manage) for the Incident Register: Superadmin/InfoSec manage, Recipient/CTO read-only.
    Uses effective VulnReg roles (own + active substitutions). Mirrors backend auth/incident_access.py."""
    if not user:
        return False, False
    if is_superadmin(user):
        return True, True
    try:
        ensure_vulnerabilities_table(conn)
        roles = _vroles(vuln_user(conn, user))
    except Exception:
        roles = set()
    can_manage = bool(roles & INCIDENT_MANAGE_ROLES)
    return can_manage or bool(roles & INCIDENT_VIEW_ROLES), can_manage


def vuln_has_role(user, role):
    return is_superadmin(user) or role in _vroles(user)


def vuln_is_admin(user):
    """VulnReg administrator: Information Security specialist (or system Superadmin). Owns Settings."""
    return vuln_has_role(user, "infosec")
VULN_IN_USE_LABELS = {"yes": "Тийм", "no": "Үгүй", "": ""}
VULN_ENV_PRESENT_LABELS = {"yes": "Тийм", "no": "Үгүй", "unknown": "Тодорхойгүй", "": ""}
VULN_COMPROMISE_LABELS = {"yes": "Тийм", "no": "Үгүй", "checking": "Шалгаж байна", "": ""}
VULN_SEVERITIES = ("critical", "high", "medium", "low")
VULN_SEV_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "none": "None", "": "Үнэлээгүй"}
VULN_DUE_SOON_SETTING = "vuln_due_soon_days"
VULN_DUE_SOON_DEFAULT = 3
VULN_FILES_DIR = DATA_DIR / "vuln_files"
VULN_FILE_SUFFIXES = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".log", ".json", ".xml",
                      ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".7z", ".html", ".md"}
# Engineer's «Нотолгоо (халдлагын баталгаа)»: files tagged category='as_evidence' on vulnerability_files.
# Images, Excel, Word, PDF and TXT.
VULN_EVIDENCE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".xls", ".xlsx", ".doc", ".docx", ".pdf", ".txt"}
VULN_FILE_CATEGORIES = ("", "as_evidence")
VULN_FILE_MAX_BYTES = 20 * 1024 * 1024
VULN_FILE_MAX_PER_UPLOAD = 10
VULN_PAGE_SIZE = 10  # fixed number of rows per page on the vulnerability list
VULN_FIELD_LABELS = {
    "reviewer_id": "Эмзэг байдлын бүртгэл хүлээн авагч",
    "title": "Нэр", "cve_id": "CVE", "source": "Илрүүлсэн эх сурвалж", "source_url": "Эх сурвалжийн холбоос",
    "published_date": "Нийтэлсэн огноо", "reported_date": "Мэдээлсэн огноо", "description": "Тайлбар",
    "scope": "Хамрах хүрээ", "verification_method": "Нөлөөллийг шалгах арга",
    "recommendation": "Засварлах зөвлөмж", "threat_trend": "Аюулын чиг хандлага", "impact": "Нөлөөлөл",
    "risk_justification": "Эрсдэлийн үндэслэл", "remediation_notes": "Засварын тэмдэглэл",
    "remediated_date": "Зассан огноо", "cvss_score": "CVSS оноо", "severity": "Түвшин",
    "due_date": "Засварлах хугацаа", "asset_id": "Хөрөнгө", "department_id": "Хэлтэс",
    "assignee_id": "Хариуцагч", "status": "Төлөв",
    "owner_custodian": "Хөрөнгө эзэмшигч / Хариуцагч", "in_use": "Ашиглагдаж байгаа эсэх",
    "affected_asset": "Нөлөөлж болзошгүй хөрөнгө / Систем",
    "env_present": "Манай орчинд энэ эмзэг байдал байгаа эсэх",
    "compromise_signs": "Халдлагад өртсөн шинж тэмдэг байгаа эсэх",
    "ia_note": "Нөлөөллийн тайлбар (InfoSec)",
    "as_scope": "Хамрах хүрээ (үнэлгээ)", "as_system_owner": "Систем ба хөрөнгийн эзэмшигч",
    "as_version": "Одоогийн хувилбар", "as_internet_facing": "Интернэтэд нээлттэй эсэх",
    "as_test_method": "Шалгасан арга", "as_evidence": "Нотолгоо (халдлагын баталгаа)",
    "as_patch_available": "Patch гарсан эсэх", "as_business_impact": "Бизнесийн нөлөө",
    "as_conclusion": "Үнэлгээний дүгнэлт", "as_affected": "Хөрөнгөд нөлөөлсөн эсэх",
    "as_exploited": "Ашиглагдсан шинж тэмдэг", "as_incident_ref": "Зөрчлийн дугаар",
    "ra_threat": "Аюул (Threat)", "ra_impacts": "Нөлөөллийн үнэлгээ (8 шалгуур)", "ra_likelihood": "Магадлал",
    "ra_level": "Эрсдэлийн түвшин", "ra_due": "Эрсдэлийн үнэлгээний хугацаа", "ra_decision": "Эрсдэлийн шийдвэр",
    "ra_decision_note": "Шийдвэрийн тайлбар", "risk_accept_reason": "Хүлээн зөвшөөрөх үндэслэл",
    "risk_accept_until": "Хүлээн зөвшөөрөх хугацаа", "rm_plan": "Засварын төлөвлөгөө", "rm_actions": "Авах арга хэмжээ",
    "rm_target_date": "Дуусгах товлосон огноо", "rm_change_ref": "Өөрчлөлтийн дугаар", "tm_controls": "Түр хамгаалалт (нөхөх хяналт)",
    "tm_until": "Түр хамгаалалтын хүчинтэй хугацаа", "avoid_note": "Зогсоосон систем / үйлчилгээ",
    "vf_note": "Баталгаажуулалтын тэмдэглэл", "closure_comment": "Хаалтын тайлбар", "residual_risk": "Үлдэгдэл эрсдэл",
    "risk_status": "Эрсдэлийн төлөв",
}
VULN_YN_LABELS = {"yes": "Тийм", "no": "Үгүй", "unknown": "Тодорхойгүй", "": ""}
VULN_DECISION_LABELS = {"mitigate": "Бууруулах (Patch / Mitigate)", "transfer": "Шилжүүлэх (Гэрээ / Даатгал / Нийлүүлэгч)",
                        "avoid": "Зайлсхийх (систем зогсоох)", "accept": "Хүлээн зөвшөөрөх (CTO зөвшөөрөл)", "": ""}
VULN_RISK_STATUS_LABELS = {"mitigated": "Бууруулсан", "residual": "Үлдэгдэл эрсдэлтэй", "accepted": "Хүлээн зөвшөөрсөн",
                           "transferred": "Шилжүүлсэн", "avoided": "Зайлсхийсэн", "not_affected": "Нөлөөлөөгүй", "": ""}
VULN_RISK_LEVEL_LABELS = {"low": "Бага (Low)", "medium": "Дунд (Medium)", "high": "Өндөр (High)", "": ""}
# MAS-14 risk assessment: 8 impact criteria (1–5), likelihood (1–5), 5×5 matrix → Low / Medium / High.
# Criteria names and the matrix thresholds are editable in Settings; these are the defaults.
VULN_RISK_SETTING = "vuln_risk_matrix"
VULN_RISK_DEFAULT = {
    "criteria": ["Санхүүгийн нөлөө", "Нэр хүнд", "Хууль эрх зүй, зохицуулалт", "Үйл ажиллагааны тасралтгүй байдал",
                 "Харилцагч / үйлчлүүлэгч", "Мэдээллийн нууцлал", "Мэдээллийн бүрэн бүтэн байдал", "Мэдээллийн хүртээмж"],
    "low_max": 4, "medium_max": 12,
}
# Risk assessment deadline (business days) by severity; the remediation SLA keeps running meanwhile.
VULN_RA_BUSINESS_DAYS = {"critical": 1, "high": 3}
VULN_RA_BUSINESS_DAYS_DEFAULT = 5


def vuln_risk_config(conn):
    cfg = json.loads(json.dumps(VULN_RISK_DEFAULT))
    raw = get_setting(conn, VULN_RISK_SETTING, "")
    if raw:
        try:
            s = json.loads(raw)
            crit = s.get("criteria")
            if isinstance(crit, list) and len(crit) == 8 and all(isinstance(c, str) and c.strip() for c in crit):
                cfg["criteria"] = [c.strip()[:120] for c in crit]
            lo, med = s.get("low_max"), s.get("medium_max")
            if isinstance(lo, int) and isinstance(med, int) and 1 <= lo < med < 25:
                cfg["low_max"], cfg["medium_max"] = lo, med
        except (ValueError, TypeError, AttributeError):
            pass
    return cfg


def vuln_risk_level(score, cfg):
    if score is None:
        return ""
    if score <= cfg["low_max"]:
        return "low"
    return "medium" if score <= cfg["medium_max"] else "high"


def vuln_add_business_days(start, n):
    d = start
    while n > 0:
        d += dt.timedelta(days=1)
        if d.weekday() < 5:
            n -= 1
    return d


def vuln_ra_due(severity, start=None):
    start = start or now_utc().date()
    n = VULN_RA_BUSINESS_DAYS.get((severity or "").lower(), VULN_RA_BUSINESS_DAYS_DEFAULT)
    return vuln_add_business_days(start, n).isoformat()
# Fields only a manager (admin / superadmin) may edit, in the order they are diffed for the activity log.
_VULN_MANAGER_FIELDS = (
    "title", "cve_id", "source", "source_url", "published_date", "reported_date", "description", "scope",
    "verification_method", "recommendation", "threat_trend", "impact", "risk_justification",
    "cvss_score", "severity", "due_date", "asset_id", "department_id", "owner_custodian", "in_use",
    "affected_asset", "env_present", "compromise_signs",
)
_VULN_REMEDIATION_FIELDS = ("remediation_notes", "remediated_date")


def vuln_can_manage(user):
    """Information Security: register/edit, risk assessment, verification, closure."""
    return vuln_has_role(user, "infosec")


def vuln_can_delete(user):
    return is_superadmin(user)


def vuln_is_receiver(user):
    """Recipient (or an active substitute): reviews new registrations, returns them, assigns engineers."""
    return "receiver" in _vroles(user)


def vuln_can_assign(user):
    return vuln_has_role(user, "receiver")


def _vuln_reviewer_ids(user):
    """User ids whose records this user handles as responsible person: themselves + principals they substitute."""
    if not user:
        return []
    try:
        extra = list(user["_vsub_for"])
    except (KeyError, IndexError, TypeError):
        extra = []
    return [user["id"]] + [i for i in extra if i != user["id"]]


def _vuln_is_reviewer(user, row):
    """The responsible person chosen at registration (or their active substitute): the Recipient for this record."""
    return bool(row["reviewer_id"]) and row["reviewer_id"] in _vuln_reviewer_ids(user)


def vuln_is_any_reviewer(user):
    try:
        return bool(user["_vreviewer"])
    except (KeyError, IndexError, TypeError):
        return False


def vuln_can_assign_record(user, row):
    """«Инженер томилох / солих» on a record — no Superadmin bypass, and never the engineer currently assigned.

    Records registered with a responsible person: only that person (or their substitute) — they act as the Recipient.
    Older records without one: the Recipient (own role or active substitute), as before.
    """
    if _vuln_is_assignee(user, row):
        return False
    if row["reviewer_id"]:
        return _vuln_is_reviewer(user, row)
    return vuln_is_receiver(user)


def vuln_can_edit_record(user, row):
    """Registration details are editable only by the InfoSec user who created the record."""
    return bool(user) and "infosec" in _vroles(user) and row["created_by"] == user["id"]


def vuln_is_cto(user):
    return vuln_has_role(user, "cto")


def _vuln_user_label(row):
    if not row:
        return ""
    return (row["display_name"] or row["username"] or row["email"] or "").strip()


def _vuln_validate(conn, user, form, existing=None):
    """Validate a create/edit form posted by a manager.

    Returns (values, errors): values maps column -> new value, errors maps form field -> message.
    Severity and the SLA remediation_days are always derived from CVSS on the server.
    """
    errors = {}
    get = lambda k: (form.get(k) or "").strip()
    limits = dict(_VULN_TEXT_LIMITS, **_VULN_EXTRA_TEXT_LIMITS)
    values = {k: get(k) for k in limits}
    values["cve_id"] = values["cve_id"].upper()
    # Fields hidden in the form designer are not posted: keep what is stored.
    kept = set()
    if existing is not None:
        for key in list(limits) + ["published_date", "reported_date", "due_date"]:
            if key not in form and key not in VULN_SECTION2_FIELDS:
                kept.add(key)
    for key in kept & set(limits):
        values[key] = existing[key] or ""
    for key, limit in limits.items():
        if len(values[key]) > limit:
            errors[key] = f"Хамгийн ихдээ {limit} тэмдэгт."
    if not values["title"]:
        errors["title"] = "Нэр заавал бөглөнө."
    if values["cve_id"] and not _CVE_RE.match(values["cve_id"]):
        errors["cve_id"] = "CVE ID буруу форматтай (жишээ: CVE-2026-12345)."
    if values["source_url"]:
        parsed = urlparse(values["source_url"])
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            errors["source_url"] = "http:// эсвэл https://-ээр эхэлсэн холбоос оруулна уу."
    today = now_utc().date().isoformat()
    for key in ("published_date", "reported_date", "due_date", "remediated_date"):
        values[key] = (existing[key] or "") if key in kept else get(key)
        if values[key] and not _valid_iso_date(values[key]) and key not in kept:
            errors[key] = "Огноо буруу форматтай байна."
    if values["published_date"] and values["published_date"] > today and "published_date" not in errors:
        errors["published_date"] = "Ирээдүйн огноо байж болохгүй."
    if values["reported_date"] and values["reported_date"] > today and "reported_date" not in errors:
        errors["reported_date"] = "Ирээдүйн огноо байж болохгүй."
    if (values["published_date"] and values["reported_date"] and values["reported_date"] < values["published_date"]
            and "reported_date" not in errors):
        errors["reported_date"] = "Нийтэлсэн огнооноос өмнө байж болохгүй."
    if values["remediated_date"] and values["remediated_date"] > today and "remediated_date" not in errors:
        errors["remediated_date"] = "Ирээдүйн огноо байж болохгүй."

    cvss = None
    cvss_raw = get("cvss_score")
    if cvss_raw:
        try:
            cvss = float(Decimal(cvss_raw).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))
            if not (0.0 <= cvss <= 10.0):
                errors["cvss_score"] = "CVSS оноо 0.0–10.0 хооронд байх ёстой."
        except (ArithmeticError, ValueError):
            errors["cvss_score"] = "CVSS оноо тоо байх ёстой."
    values["cvss_score"] = cvss
    if existing is not None and _vuln_same(existing["cvss_score"], cvss):
        # CVSS unchanged: keep the severity/SLA assigned at registration, even if the policy changed since
        # (open records are re-evaluated only through Settings → "Дахин тооцоолох").
        severity, remediation_days = existing["severity"], existing["remediation_days"]
    else:
        severity, remediation_days = cvss_severity(cvss, vuln_sla(conn))
        if "due_date" in kept:
            values["due_date"] = ""  # hidden deadline follows the new CVSS
    values["severity"] = severity
    values["remediation_days"] = remediation_days
    if not values["due_date"] and remediation_days is not None and "reported_date" not in errors:
        base = dt.date.fromisoformat(values["reported_date"]) if values["reported_date"] else now_utc().date()
        values["due_date"] = (base + dt.timedelta(days=remediation_days)).isoformat()

    # Asset: optional; must exist and (for non-superadmins) belong to the user's own department.
    asset_id = None
    asset_raw = get("asset_id")
    asset_row = None
    if asset_raw:
        if asset_raw.isdigit():
            asset_row = conn.execute("SELECT id, department_id FROM assets WHERE id = ?", (int(asset_raw),)).fetchone()
        if not asset_row:
            errors["asset_id"] = "Сонгосон хөрөнгө олдсонгүй."
            asset_row = None
        else:
            asset_id = asset_row["id"]
    elif "asset_id" not in form and existing is not None:
        asset_id = existing["asset_id"]  # form now enters the asset as text; keep any older register link
        if asset_id and not existing["affected_asset"] and values["affected_asset"]:
            linked = conn.execute("SELECT asset_name FROM assets WHERE id = ?", (asset_id,)).fetchone()
            if linked and values["affected_asset"] == (linked["asset_name"] or "").strip():
                values["affected_asset"] = ""  # prefilled from the linked asset, not an actual edit
    values["asset_id"] = asset_id

    in_use = get("in_use")
    if in_use not in VULN_IN_USE_LABELS:
        errors["in_use"] = "Тийм эсвэл Үгүй сонгоно уу."
        in_use = ""
    values["in_use"] = in_use
    for key, labels in (("env_present", VULN_ENV_PRESENT_LABELS), ("compromise_signs", VULN_COMPROMISE_LABELS)):
        v = get(key)
        if v not in labels:
            errors[key] = "Жагсаалтаас сонгоно уу."
            v = ""
        values[key] = v
    # Section 2 (asset and responsibility) is completed by the assigned engineer, not on the InfoSec form:
    # keep whatever is stored when the form does not send these fields.
    for key in VULN_SECTION2_FIELDS:
        if key not in form:
            values[key] = (existing[key] or "") if existing is not None else ""
            errors.pop(key, None)

    # Department is not entered on the form: it follows the asset, else stays as stored, else the registrant's.
    if asset_row:
        values["department_id"] = asset_row["department_id"]
    elif existing is not None:
        values["department_id"] = existing["department_id"]
    else:
        values["department_id"] = user["department_id"]
    # Required flags set by InfoSec in the form designer (built-in registration fields).
    reg = vuln_form_schema(conn, "register")
    for f in _vuln_form_fields(reg):
        if f["builtin"] and not f["block"] and f["required"] and not f["hidden"] and f["key"] in values:
            if values[f["key"]] in (None, "") and f["key"] not in errors:
                errors[f["key"]] = "Заавал бөглөнө."
    return values, errors


def _vuln_log(conn, vuln_id, user, action, field="", old="", new="", note=""):
    conn.execute(
        """INSERT INTO vulnerability_activity(vulnerability_id, actor_user_id, actor_name, action, field,
               old_value, new_value, note, created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
        (vuln_id, user["id"] if user else None, _vuln_user_label(user) if user else "", action, field,
         "" if old is None else str(old), "" if new is None else str(new), note or "", now_utc().isoformat()),
    )


def _vuln_notify(users, subject, lines, vuln_id):
    """E-mail each user (skips users without an address; no-op when SMTP is not configured)."""
    link = APP_URL.rstrip("/") + (f"/registry/vulnerabilities/{vuln_id}" if vuln_id else "/registry/vulnerabilities")
    body = "\n".join(lines + ["", f"Дэлгэрэнгүй: {link}"])
    sent = set()
    for u in users:
        addr = (u["email"] or "").strip() if u else ""
        if addr and addr.lower() not in sent:
            sent.add(addr.lower())
            _send_async(addr, subject, body)


def _vuln_role_users(conn, role):
    """Active holders of a VulnReg role, plus anyone substituting for that role today."""
    today = _vuln_today()
    return conn.execute(
        """SELECT * FROM users WHERE is_active = 1 AND (""" + _VULN_HAS_ROLE_SQL.format(col="vuln_role") + """ OR id IN (
               SELECT substitute_id FROM vuln_substitutes WHERE role = ? AND revoked_at = ''
               AND start_date <= ? AND end_date >= ?))""", (role, role, today, today)).fetchall()


def _vuln_receivers(conn):
    return _vuln_role_users(conn, "receiver")


def _vuln_notify_receivers(conn, actor, vuln_id, resubmitted=False, ids=None):
    """Tell the Recipient(s) and their substitutes that a registration awaits review (one mail per registration)."""
    ids = ids or [vuln_id]
    rows = [conn.execute(f"{_VULN_SELECT_SQL} WHERE v.id = ?", (i,)).fetchone() for i in ids]
    row = rows[0]
    what = "засварлаж дахин илгээлээ" if resubmitted else "бүртгэлээ"
    lines = [
        f"{_vuln_user_label(actor)} эмзэг байдал {what}. Хянаж, нөлөөлөх хөрөнгө бүрт хариуцах инженер томилно уу.",
        "",
        f"{row['cve_id'] + ' — ' if row['cve_id'] else ''}{row['title']}",
        f"Түвшин: {VULN_SEV_LABELS.get((row['severity'] or '').lower(), row['severity'])}"
        + (f" (CVSS {row['cvss_score']:.1f})" if row["cvss_score"] is not None else ""),
        f"Засварлах хугацаа (SLA): {row['due_date'] or '—'}",
        "",
        "Нөлөөлөх хөрөнгө:",
    ] + [f"  • {_vuln_ref(r)} — {r['asset_name'] or '—'}" for r in rows]
    _vuln_notify(_vuln_receivers(conn), f"[Эмзэг байдал] {_vuln_ref(row)} хянах хүсэлт", lines, vuln_id)


def _vuln_notify_closed(conn, actor, row, status):
    """Step 8: once a finding is closed, notify the Recipient and the CTO (and their substitutes)."""
    users = list(_vuln_role_users(conn, "receiver")) + list(_vuln_role_users(conn, "cto"))
    if row["reviewer_id"]:
        users.append(_vuln_user_by_id(conn, row["reviewer_id"]))  # acted as the Recipient for this record
    _vuln_notify(users, f"[Эмзэг байдал] {_vuln_ref(row)} хаагдлаа", [
        f"{_vuln_user_label(actor)} дараах эмзэг байдлын бүртгэлийг хаалаа.", "",
        f"{_vuln_ref(row)} — {row['title']}",
        f"Мэдээллийн хөрөнгө / Систем: {row['asset_name'] or '—'}",
        f"Эцсийн төлөв: {VULN_STATUS_LABELS.get(status, status)}",
    ], row["id"])


def _vuln_insert(conn, user, values, group_id=None):
    """Insert one finding in status New; vuln_api_create then assigns the chosen responsible person."""
    ts = now_utc().isoformat()
    cur = conn.execute(
        """INSERT INTO vulnerabilities(cve_id, title, source, source_url, published_date, reported_date,
               description, scope, verification_method, recommendation, threat_trend, impact, risk_justification,
               remediation_notes, cvss_score, severity, remediation_days, due_date, department_id, asset_id,
               owner_custodian, in_use, affected_asset, env_present, compromise_signs,
               status, created_by, updated_by, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (values["cve_id"], values["title"], values["source"], values["source_url"], values["published_date"],
         values["reported_date"], values["description"], values["scope"], values["verification_method"],
         values["recommendation"], values["threat_trend"], values["impact"], values["risk_justification"],
         values["remediation_notes"], values["cvss_score"], values["severity"], values["remediation_days"],
         values["due_date"], values["department_id"], values["asset_id"], values["owner_custodian"], values["in_use"],
         values.get("affected_asset", ""), values.get("env_present", ""), values.get("compromise_signs", ""),
         "new", user["id"], user["id"], ts, ts),
    )
    vuln_id = cur.lastrowid
    conn.execute("UPDATE vulnerabilities SET group_id = ?, vuln_custom = ? WHERE id = ?",
                 (group_id or vuln_id, values.get("vuln_custom") or "{}", vuln_id))
    _vuln_log(conn, vuln_id, user, "created", "status", "", "new")
    label = f"{values['cve_id']} — {values['title']}" if values["cve_id"] else values["title"]
    record_audit(conn, user["id"], "create", "vulnerability", entity_id=vuln_id,
                 department_id=values["department_id"], details=f"Эмзэг байдал бүртгэв: {label}")
    return vuln_id


VULN_DASHBOARD_TEMPLATE = BASE_DIR / "templates" / "vuln_dashboard.html"


def _script_json(value):
    """JSON safe to embed inside a <script> element."""
    return (json.dumps(value, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _vuln_scope(user):
    """SQL predicate limiting rows to what the user may see.

    Roles with the "view_all" permission (Settings → access) see every record; otherwise a user sees what is
    assigned to them or registered by them, plus the queue their role must act on. Soft-deleted rows never show.
    """
    if vuln_perm(user, "view_all"):
        return "v.deleted_at = ''", []
    parts, args = ["v.assignee_id = ?", "v.created_by = ?"], [user["id"], user["id"]]
    rids = _vuln_reviewer_ids(user)
    parts.append(f"v.reviewer_id IN ({','.join('?' * len(rids))})")
    args += rids
    if vuln_is_receiver(user):
        parts.append("(v.status = 'new' AND v.reviewer_id IS NULL)")
    if vuln_has_role(user, "cto"):
        parts.append("v.status = 'pending_cto'")
    return f"v.deleted_at = '' AND ({' OR '.join(parts)})", args


def _uname_sql(alias):
    return f"COALESCE(NULLIF({alias}.display_name, ''), {alias}.username, {alias}.email, '')"


_VULN_REF_SQL = "('VUL-' || substr(v.created_at, 1, 4) || '-' || printf('%04d', v.id))"
_VULN_FROM_SQL = f"""
    FROM vulnerabilities v
    LEFT JOIN departments d ON d.id = v.department_id
    LEFT JOIN assets a ON a.id = v.asset_id
    LEFT JOIN departments ad ON ad.id = a.department_id
    LEFT JOIN users cu ON cu.id = v.created_by
    LEFT JOIN users au ON au.id = v.assignee_id
    LEFT JOIN users ru ON ru.id = v.risk_accept_approver_id
    LEFT JOIN users rv ON rv.id = v.reviewer_id
"""
_VULN_SELECT_SQL = f"""
    SELECT v.*, d.name AS department_name, COALESCE(NULLIF(v.affected_asset, ''), a.asset_name) AS asset_name, a.asset_type, a.owner AS asset_owner,
           a.custodian AS asset_custodian, a.location AS asset_location, a.asset_category AS asset_category,
           ad.name AS asset_department_name,
           {_uname_sql('cu')} AS created_by_name, {_uname_sql('au')} AS assignee_name,
           {_uname_sql('ru')} AS risk_approver_name, {_uname_sql('rv')} AS reviewer_name
""" + _VULN_FROM_SQL
_VULN_SEV_RANK_SQL = ("CASE lower(v.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                      "WHEN 'low' THEN 3 WHEN 'none' THEN 4 ELSE 5 END")
_VULN_STATUS_RANK_SQL = "CASE v.status " + " ".join(
    f"WHEN '{s}' THEN {i}" for i, s in enumerate(VULN_STATUS_ORDER)) + " ELSE 99 END"
_VULN_OPEN_SQL = "v.status NOT IN (" + ", ".join(f"'{s}'" for s in VULN_CLOSED_STATUSES) + ")"
_VULN_SORTS = {
    "ref": "v.id",
    "title": "ulower(v.title)",
    "cve": "v.cve_id",
    "asset": "ulower(COALESCE(NULLIF(v.affected_asset, ''), a.asset_name, ''))",
    "dept": "ulower(COALESCE(d.name, ''))",
    "severity": _VULN_SEV_RANK_SQL,
    "status": _VULN_STATUS_RANK_SQL,
    "created": "v.created_at",
    "assignee": "ulower(" + _uname_sql("au") + ")",
}


def _vuln_prepare_conn(conn):
    """Unicode-aware lower() so Cyrillic search and sorting are case-insensitive (SQLite lower() is ASCII-only)."""
    conn.create_function("ulower", 1, lambda s: s.lower() if isinstance(s, str) else s, deterministic=True)
    ensure_vulnerabilities_table(conn)


def vuln_soon_days(conn):
    """'Approaching deadline' threshold in days: app_settings[vuln_due_soon_days], else 3."""
    raw = get_setting(conn, VULN_DUE_SOON_SETTING, "")
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return VULN_DUE_SOON_DEFAULT
    return n if 0 <= n <= 90 else VULN_DUE_SOON_DEFAULT


def _vuln_deadline(status, due, today, soon_days):
    if status in VULN_CLOSED_STATUSES:
        return {"kind": "done", "days": None}
    if not due:
        return {"kind": "none", "days": None}
    try:
        n = (dt.date.fromisoformat(due) - today).days
    except ValueError:
        return {"kind": "none", "days": None}
    kind = "overdue" if n < 0 else ("soon" if n <= soon_days else "ontrack")
    return {"kind": kind, "days": n}


def _vuln_ref(r):
    return f"VUL-{(r['created_at'] or '')[:4] or '0000'}-{r['id']:04d}"


def _vuln_like(token):
    return "%" + token.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _vuln_int(value):
    value = (value or "").strip()
    return int(value) if value.isdigit() and len(value) < 12 else None


def _vuln_todo_sql(user):
    """SQL predicate: records waiting on this user's action (same rules as vuln_available_actions).

    Engineer: assigned records to fill in / remediate / confirm shutdown. Responsible person (acting Recipient): new
    records to review and assign (the Recipient for older records registered without one).
    InfoSec: risk assessment, verification, closing a confirmed shutdown, and own returned records. CTO: risk acceptances.
    """
    parts, args = [], []
    parts.append("(v.assignee_id = ? AND (v.status IN ('assigned', 'under_assessment', 'remediation')"
                 " OR (v.status = 'avoidance' AND v.avoid_confirmed_at = '')))")
    args.append(user["id"])
    rids = _vuln_reviewer_ids(user)
    parts.append(f"(v.status = 'new' AND v.reviewer_id IN ({','.join('?' * len(rids))}))")
    args += rids
    if vuln_is_receiver(user):
        parts.append("(v.status = 'new' AND v.reviewer_id IS NULL)")
    if vuln_can_manage(user):
        parts.append("v.status IN ('risk_assessment', 'verification')")
        parts.append("(v.status = 'avoidance' AND v.avoid_confirmed_at <> '')")
        parts.append("(v.status = 'returned' AND v.created_by = ?)")
        args.append(user["id"])
    if vuln_is_cto(user):
        parts.append("v.status = 'pending_cto'")
    return "(" + " OR ".join(parts) + ")", args


def vuln_todo_count(conn, user):
    scope_sql, scope_args = _vuln_scope(user)
    todo_sql, todo_args = _vuln_todo_sql(user)
    return conn.execute(f"SELECT COUNT(*) FROM vulnerabilities v WHERE {scope_sql} AND {todo_sql}",
                        scope_args + todo_args).fetchone()[0]


def _vuln_filters(query, user, today, soon_days):
    """Translate query-string filters into SQL. Unknown/invalid values are ignored, not errors."""
    where, args = [], []
    q = qs_value(query, "q").strip()[:200]
    for token in q.lower().split()[:8]:
        like = _vuln_like(token)
        where.append(
            f"(ulower({_VULN_REF_SQL}) LIKE ? ESCAPE '\\' OR ulower(v.title) LIKE ? ESCAPE '\\' "
            "OR ulower(v.cve_id) LIKE ? ESCAPE '\\' OR ulower(COALESCE(NULLIF(v.affected_asset, ''), a.asset_name, '')) LIKE ? ESCAPE '\\' "
            "OR CAST(v.asset_id AS TEXT) = ? OR CAST(v.id AS TEXT) = ?)"
        )
        args += [like, like, like, like, token, token]
    if qs_value(query, "todo") == "1":
        todo_sql, todo_args = _vuln_todo_sql(user)
        where.append(todo_sql)
        args += todo_args
    sev = qs_value(query, "sev").lower()
    if sev in VULN_SEVERITIES:
        where.append("lower(v.severity) = ?")
        args.append(sev)
    status = qs_value(query, "status")
    if status == "open":
        where.append(_VULN_OPEN_SQL)
    elif status in VULN_STATUS_LABELS:
        where.append("v.status = ?")
        args.append(status)
    asset = _vuln_int(qs_value(query, "asset"))
    if asset is not None:
        where.append("v.asset_id = ?")
        args.append(asset)
    dept = _vuln_int(qs_value(query, "dept"))
    if dept is not None:
        where.append("v.department_id = ?")
        args.append(dept)
    assignee = qs_value(query, "assignee")
    if assignee == "me":
        where.append("v.assignee_id = ?")
        args.append(user["id"])
    elif assignee == "none":
        where.append("v.assignee_id IS NULL")
    elif _vuln_int(assignee) is not None:
        where.append("v.assignee_id = ?")
        args.append(_vuln_int(assignee))
    for key, expr, op in (("reg_from", "substr(v.created_at, 1, 10)", ">="), ("reg_to", "substr(v.created_at, 1, 10)", "<="),
                          ("due_from", "v.due_date", ">="), ("due_to", "v.due_date", "<=")):
        value = qs_value(query, key)
        if value and _valid_iso_date(value):
            where.append(f"{expr} <> '' AND {expr} {op} ?")
            args.append(value)
    deadline = qs_value(query, "deadline")
    t = today.isoformat()
    soon = (today + dt.timedelta(days=soon_days)).isoformat()
    if deadline == "overdue":
        where.append(f"{_VULN_OPEN_SQL} AND v.due_date <> '' AND v.due_date < ?")
        args.append(t)
    elif deadline == "soon":
        where.append(f"{_VULN_OPEN_SQL} AND v.due_date >= ? AND v.due_date <= ?")
        args += [t, soon]
    elif deadline == "ontrack":
        where.append(f"{_VULN_OPEN_SQL} AND v.due_date > ?")
        args.append(soon)
    elif deadline == "none":
        where.append(f"{_VULN_OPEN_SQL} AND v.due_date = ''")
    return where, args


def _vuln_order_sql(query):
    key = qs_value(query, "sort")
    direction = "ASC" if qs_value(query, "dir").lower() == "asc" else "DESC"
    if key == "due":
        # Records without a deadline always sort last.
        return f"CASE WHEN v.due_date = '' THEN 1 ELSE 0 END, v.due_date {direction}, v.id DESC"
    expr = _VULN_SORTS.get(key)
    if not expr:
        return "v.id DESC"
    return f"{expr} {direction}, v.id DESC"


def _vuln_list_item(r, today, soon_days):
    sev = (r["severity"] or "").lower()
    return {
        "id": r["id"],
        "ref": _vuln_ref(r),
        "title": r["title"],
        "cve": r["cve_id"],
        "asset": {"id": r["asset_id"], "name": r["asset_name"] or ""} if (r["asset_id"] or r["asset_name"]) else None,
        "dept": r["department_name"] or "",
        "deptId": r["department_id"],
        "severity": sev if sev in VULN_SEV_LABELS else "",
        "cvss": r["cvss_score"],
        "status": r["status"] or "new",
        "statusLabel": VULN_STATUS_LABELS.get(r["status"] or "new", r["status"]),
        "created": (r["created_at"] or "")[:10],
        "due": r["due_date"] or "",
        "deadline": _vuln_deadline(r["status"], r["due_date"], today, soon_days),
        "assignee": {"id": r["assignee_id"], "name": r["assignee_name"] or ""} if r["assignee_id"] else None,
    }


def vuln_kpis(conn, user, today, soon_days):
    scope_sql, scope_args = _vuln_scope(user)
    t = today.isoformat()
    soon = (today + dt.timedelta(days=soon_days)).isoformat()
    row = conn.execute(
        f"""SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN {_VULN_OPEN_SQL} THEN 1 ELSE 0 END), 0) AS open,
                   COALESCE(SUM(CASE WHEN v.status IN ('under_assessment', 'risk_assessment', 'pending_cto', 'remediation',
                                     'verification', 'temp_mitigation', 'avoidance') THEN 1 ELSE 0 END), 0) AS working,
                   COALESCE(SUM(CASE WHEN v.status IN ('closed', 'not_affected', 'transferred') THEN 1 ELSE 0 END), 0) AS closed,
                   COALESCE(SUM(CASE WHEN {_VULN_OPEN_SQL} AND lower(v.severity) = 'critical' THEN 1 ELSE 0 END), 0) AS critical,
                   COALESCE(SUM(CASE WHEN {_VULN_OPEN_SQL} AND lower(v.severity) = 'high' THEN 1 ELSE 0 END), 0) AS high,
                   COALESCE(SUM(CASE WHEN {_VULN_OPEN_SQL} AND lower(v.severity) = 'critical' AND v.due_date <> ''
                                     AND v.due_date < ? THEN 1 ELSE 0 END), 0) AS critical_overdue,
                   COALESCE(SUM(CASE WHEN {_VULN_OPEN_SQL} AND v.due_date <> '' AND v.due_date < ? THEN 1 ELSE 0 END), 0) AS overdue,
                   COALESCE(SUM(CASE WHEN {_VULN_OPEN_SQL} AND v.due_date >= ? AND v.due_date <= ? THEN 1 ELSE 0 END), 0) AS soon
            FROM vulnerabilities v WHERE {scope_sql}""",
        [t, t, t, soon] + scope_args,
    ).fetchone()
    return dict(row)


def vuln_api_list(conn, user, query):
    today = now_utc().date()
    soon_days = vuln_soon_days(conn)
    scope_sql, scope_args = _vuln_scope(user)
    where, args = _vuln_filters(query, user, today, soon_days)
    where_sql = " AND ".join([scope_sql] + where)
    all_args = scope_args + args
    total = conn.execute(f"SELECT COUNT(*) {_VULN_FROM_SQL} WHERE {where_sql}", all_args).fetchone()[0]
    per = VULN_PAGE_SIZE
    pages = max(1, -(-total // per))
    page = min(max(_vuln_int(qs_value(query, "page")) or 1, 1), pages)
    rows = conn.execute(
        f"{_VULN_SELECT_SQL} WHERE {where_sql} ORDER BY {_vuln_order_sql(query)} LIMIT ? OFFSET ?",
        all_args + [per, (page - 1) * per],
    ).fetchall()
    return {
        "rows": [_vuln_list_item(r, today, soon_days) for r in rows],
        "total": total, "page": page, "pages": pages, "per": per,
        "kpis": vuln_kpis(conn, user, today, soon_days),
        "todoCount": vuln_todo_count(conn, user),
        "today": today.isoformat(), "soonDays": soon_days,
    }


def vuln_api_options(conn, user):
    """Reference data for filters and forms, limited to what the user may use."""
    departments = [{"id": r["id"], "name": r["name"]} for r in conn.execute("SELECT id, name FROM departments ORDER BY name")]
    if vuln_can_manage(user) or vuln_perm(user, "view_all"):
        asset_rows = conn.execute(
            "SELECT a.id, a.asset_name, a.owner, a.custodian, d.name AS dept FROM assets a "
            "LEFT JOIN departments d ON d.id = a.department_id ORDER BY a.asset_name").fetchall()
    else:
        asset_rows = conn.execute(
            """SELECT a.id, a.asset_name, a.owner, a.custodian, d.name AS dept FROM assets a LEFT JOIN departments d ON d.id = a.department_id
               WHERE a.id IN (SELECT asset_id FROM vulnerabilities WHERE assignee_id = ? AND deleted_at = '')
               ORDER BY a.asset_name""", (user["id"],)).fetchall()
    assets = [{"id": r["id"], "name": r["asset_name"], "dept": r["dept"] or "",
               "owner": r["owner"] or "", "custodian": r["custodian"] or ""} for r in asset_rows]
    users = []
    if vuln_can_manage(user) or vuln_can_assign(user) or vuln_is_any_reviewer(user):
        # Assignee filter + engineer picker: only people who hold a VulnReg role.
        users = [{"id": r["id"], "name": _vuln_user_label(r), "dept": r["dept"] or "", "roles": vuln_roles_of(r)}
                 for r in conn.execute(
            """SELECT u.id, u.display_name, u.username, u.email, u.vuln_role, d.name AS dept FROM users u
               LEFT JOIN departments d ON d.id = u.department_id WHERE u.is_active = 1 AND u.vuln_role <> ''
               ORDER BY COALESCE(NULLIF(u.display_name, ''), u.username)""")]
    return {
        "departments": departments, "assets": assets, "users": users,
        "engineers": [u for u in users if "engineer" in u["roles"]],
        # «Хүлээн авагч сонгох» at registration: only active users holding the «Хүлээн авагч» (receiver) role.
        "people": [{"id": r["id"], "name": _vuln_user_label(r), "dept": r["dept"] or ""} for r in conn.execute(
            """SELECT u.id, u.display_name, u.username, u.email, d.name AS dept FROM users u
               LEFT JOIN departments d ON d.id = u.department_id WHERE u.is_active = 1 AND """
            + _VULN_HAS_ROLE_SQL.format(col="u.vuln_role") + """
               ORDER BY COALESCE(NULLIF(u.display_name, ''), u.username)""", ("receiver",))] if vuln_can_manage(user) else [],
        "statuses": [{"key": k, "label": VULN_STATUS_LABELS[k]} for k in VULN_STATUS_ORDER],
        "assetForm": _vuln_asset_form_meta(user) if vuln_can_manage(user) else None,
        "sla": vuln_sla(conn),
        "risk": vuln_risk_config(conn),
    }


def _vuln_asset_form_meta(user):
    """Field definitions for registering a new asset from the vulnerability form (same rules as the asset register)."""
    def opts(field):
        return [{"value": o[1], "label": o[0]} if isinstance(o, tuple) else {"value": o, "label": o}
                for o in DROPDOWN_OPTIONS.get(field, [])]
    codes = [{"value": code, "label": f"{code} — {name}", "group": group}
             for group, rows in KOD_TABLE_DATA for name, code, _ in rows]
    known = {c["value"] for c in codes}
    codes += [{"value": c, "label": c, "group": ""} for c in DROPDOWN_OPTIONS["asset_group_code"] if c not in known]
    fields = []
    for field, label, required in ASSET_FIELDS:
        if field in ASSET_COMPUTED_FIELDS:
            continue
        fields.append({"name": field, "label": label, "required": required,
                       "options": codes if field == "asset_group_code" else (opts(field) or None)})
    return {
        "fields": fields,
        "frequencies": FREQUENCY_OPTIONS,
        "deptLocked": False,
        "deptId": user["department_id"],
    }


def vuln_api_create_asset(conn, user, form):
    """Register a new asset in the asset register from inside the vulnerability form.

    Uses the asset register's own validator. Admins may only add to their own department
    (matching which assets they may link to a vulnerability); a superadmin picks the department.
    """
    if not vuln_can_manage(user):
        return 403, {"error": "Хөрөнгө бүртгэх эрхгүй."}
    # InfoSec registers affected assets organisation-wide, so the department is chosen on the form.
    dept_raw = (form.get("department_id") or "").strip()
    dept_id = int(dept_raw) if dept_raw.isdigit() else None
    department = conn.execute("SELECT * FROM departments WHERE id = ?", (dept_id,)).fetchone() if dept_id else None
    if not department:
        return 400, {"error": "Хэлтэс сонгоно уу.", "fields": {"department_id": "Хэлтэс сонгоно уу."}}
    permissions = get_department_permissions(conn, department["id"])
    values, error = validate_asset_form(form, user, permissions)
    if error:
        field = next((f for f, label, _ in ASSET_FIELDS if error.startswith(label)), None)
        return 400, {"error": error, "fields": {field: error} if field else {}}
    if len(values["asset_name"]) > 300:
        return 400, {"error": "Нэр хэт урт байна.", "fields": {"asset_name": "Хамгийн ихдээ 300 тэмдэгт."}}
    dup = conn.execute("SELECT id FROM assets WHERE department_id = ? AND lower(trim(asset_name)) = lower(?)",
                       (department["id"], values["asset_name"])).fetchone()
    if dup:
        msg = f"Энэ хэлтэст ийм нэртэй хөрөнгө (#{dup['id']}) бүртгэлтэй байна. Жагсаалтаас сонгоно уу."
        return 409, {"error": msg, "fields": {"asset_name": msg}, "existingId": dup["id"]}
    asset_id = insert_asset(conn, department["id"], values)
    record_audit(conn, user["id"], "create", "asset", entity_id=asset_id, department_id=department["id"],
                 details=f"{values['asset_name']} хөрөнгө үүслээ (эмзэг байдлын бүртгэлээс).")
    conn.commit()
    return 200, {"asset": {"id": asset_id, "name": values["asset_name"], "dept": department["name"], "deptId": department["id"],
                           "owner": values.get("owner", ""), "custodian": values.get("custodian", "")}}


def vuln_get(conn, user, vuln_id):
    scope_sql, scope_args = _vuln_scope(user)
    return conn.execute(f"{_VULN_SELECT_SQL} WHERE v.id = ? AND {scope_sql}", [vuln_id] + scope_args).fetchone()


def _vuln_is_assignee(user, row):
    return bool(row["assignee_id"]) and row["assignee_id"] == user["id"]


def vuln_available_actions(user, row):
    """Workflow actions this user may perform on the record now (server-side source of truth)."""
    status = row["status"] or "new"
    out = []
    for key, (froms, actor, _label) in VULN_ACTIONS.items():
        if status not in froms:
            continue
        if actor == "assignee":
            # The assigned engineer acts; InfoSec may also maintain the engineer's drafts and resume work.
            ok = (_vuln_is_assignee(user, row) or is_superadmin(user)
                  or (vuln_can_manage(user) and key in ("save_assessment", "save_remediation", "temp_resume")))
        elif key == "return" and row["reviewer_id"]:
            ok = _vuln_is_reviewer(user, row)  # the responsible person acts as the Recipient for this record
        else:
            ok = vuln_has_role(user, actor)
        if key == "resubmit" and not vuln_can_edit_record(user, row):
            ok = False  # "Засаад дахин илгээх" belongs with editing: only the InfoSec user who created the record
        if key == "avoid_close" and not row["avoid_confirmed_at"]:
            ok = False
        if key == "verify_temp" and row["rm_fix_type"] != "temp":
            ok = False
        # Segregation of duties (a person may hold several roles): nobody approves the risk acceptance they
        # requested, and nobody verifies / closes the fix they implemented themselves.
        if key in ("cto_approve", "cto_reject") and row["risk_accept_requested_by"] == user["id"]:
            ok = False
        if key in ("verify_fail", "verify_temp", "close") and _vuln_is_assignee(user, row):
            ok = False
        if ok:
            out.append(key)
    return out


_VULN_SILENT_FIELDS = {"status", "updated_at", "updated_by", "closed_at", "as_submitted_at", "ra_assessed_by", "ra_assessed_at",
                       "ra_impact", "ra_score", "risk_accept_requested_by", "risk_accept_approver_id", "rm_fix_type",
                       "avoid_confirmed_at", "ia_decided_by", "ia_decided_at"}
_VULN_ACTION_EVENTS = {
    "submit_assessment": "assessment_submitted", "risk_assess": "risk_assessed", "cto_approve": "cto_approved",
    "cto_reject": "cto_rejected", "avoid_confirm": "avoid_confirmed", "submit_fix": "fix_submitted",
    "submit_temp": "temp_submitted", "cannot_remediate": "cannot_remediate", "verify_fail": "verify_failed",
    "verify_temp": "verify_temp", "close": "closed", "avoid_close": "closed",
}


def _vuln_apply(conn, user, row, cols, note="", event="", audit_label=""):
    """Persist column changes; every changed field and the status change go to the append-only activity log."""
    changed = {c: v for c, v in cols.items() if not _vuln_same(row[c], v)}
    if changed:
        upd = dict(changed, updated_at=now_utc().isoformat(), updated_by=user["id"] if user else None)
        conn.execute("UPDATE vulnerabilities SET " + ", ".join(f"{c} = ?" for c in upd) + " WHERE id = ?",
                     list(upd.values()) + [row["id"]])
    for field, new in changed.items():
        if field == "vuln_custom":
            _vuln_custom_log(conn, row, user, vuln_custom_values(row), json.loads(new or "{}"))
        elif field not in _VULN_SILENT_FIELDS:
            _vuln_log(conn, row["id"], user, "updated", field, _vuln_display(conn, field, row[field]),
                      _vuln_display(conn, field, new))
    if event:
        _vuln_log(conn, row["id"], user, event, "", "", "", note)
    if "status" in changed:
        _vuln_log(conn, row["id"], user, "status_changed", "status", row["status"], changed["status"], "" if event else note)
    if changed or event:
        what = audit_label or ", ".join(("Нэмэлт талбар" if f == "vuln_custom" else VULN_FIELD_LABELS.get(f, f))
                                        for f in changed if f not in _VULN_SILENT_FIELDS)
        st = (f" ({VULN_STATUS_LABELS.get(row['status'], row['status'])} → {VULN_STATUS_LABELS.get(changed['status'], changed['status'])})"
              if "status" in changed else "")
        record_audit(conn, user["id"] if user else None, "update", "vulnerability", entity_id=row["id"],
                     department_id=row["department_id"], details=f"{_vuln_ref(row)}: {what}{st}")
    return changed


def _vf(form, key, limit=10000):
    return (form.get(key) or "").strip()[:limit]


def _vuln_fail(errors):
    return 422, {"error": "Талбаруудыг шалгана уу.", "fields": errors}


def _vuln_reload(conn, row):
    return conn.execute(f"{_VULN_SELECT_SQL} WHERE v.id = ?", (row["id"],)).fetchone()


def _vuln_user_by_id(conn, uid):
    return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None


def _vuln_record_lines(row):
    return [f"{_vuln_ref(row)} — {row['title']}", f"Мэдээллийн хөрөнгө / Систем: {row['asset_name'] or '—'}",
            f"Түвшин: {VULN_SEV_LABELS.get((row['severity'] or '').lower(), row['severity'])}"
            + (f" (CVSS {row['cvss_score']:.1f})" if row["cvss_score"] is not None else "")]


VULN_SECTION2_FIELDS = ("affected_asset", "owner_custodian", "in_use", "env_present", "compromise_signs")


def _vuln_section2_values(form, row):
    """Section 2 as entered by the assigned engineer (fields not posted keep their stored value)."""
    values, errors = {}, {}
    for f, limit in (("affected_asset", 300), ("owner_custodian", 300)):
        values[f] = _vf(form, f, limit) if f in form else (row[f] or "")
    for f, labels in (("in_use", VULN_IN_USE_LABELS), ("env_present", VULN_ENV_PRESENT_LABELS),
                      ("compromise_signs", VULN_COMPROMISE_LABELS)):
        v = _vf(form, f, 20) if f in form else (row[f] or "")
        if v not in labels:
            errors[f] = "Жагсаалтаас сонгоно уу."
            v = ""
        values[f] = v
    return values, errors


_VULN_ASSESS_TEXT = ("as_scope", "as_system_owner", "as_version", "as_test_method", "as_evidence",
                     "as_conclusion", "as_incident_ref")
_VULN_ASSESS_CHOICE = {"as_internet_facing": ("yes", "no"), "as_patch_available": ("yes", "no", "unknown"),
                       "as_affected": ("yes", "no"), "as_exploited": ("yes", "no")}


def _vuln_assessment_values(form, row):
    values, errors = {}, {}
    for f in _VULN_ASSESS_TEXT:
        values[f] = _vf(form, f, 300 if f == "as_incident_ref" else 10000) if f in form else (row[f] or "")
    for f, choices in _VULN_ASSESS_CHOICE.items():
        if f == "as_affected":
            continue  # decided by InfoSec (in the risk assessment), not by the engineer
        v = _vf(form, f, 20) if f in form else (row[f] or "")
        if v and v not in choices:
            errors[f] = "Сонголт буруу."
            v = ""
        values[f] = v
    return values, errors


def _vuln_flag_incident(conn, user, row, values):
    """Signs of exploitation → the separate Incident Management process must be started."""
    if values.get("as_exploited") != "yes" or row["as_exploited"] == "yes":
        return None
    note = "Эмзэг байдал ашиглагдсан шинж тэмдэг илэрсэн — Зөрчлийн удирдлагын процессыг эхлүүлэх шаардлагатай."
    _vuln_log(conn, row["id"], user, "incident_flagged", "", "", values.get("as_incident_ref") or "", note)
    users = list(_vuln_role_users(conn, "infosec")) + list(_vuln_role_users(conn, "receiver"))
    if row["reviewer_id"]:
        users.append(_vuln_user_by_id(conn, row["reviewer_id"]))  # acted as the Recipient for this record
    lines = [f"{_vuln_user_label(user)} үнэлгээний явцад эмзэг байдал ашиглагдсан шинж тэмдэг (сэжигтэй лог, хандалт) илрүүллээ.",
             "Зөрчлийн удирдлагын процессыг тусад нь эхлүүлнэ үү: " + APP_URL.rstrip("/") + "/incidents/", ""] + _vuln_record_lines(row)
    if values.get("as_incident_ref"):
        lines.append(f"Зөрчлийн дугаар: {values['as_incident_ref']}")
    return lambda: _vuln_notify(users, f"[ЯАРАЛТАЙ] {_vuln_ref(row)} — ашиглагдсан шинж тэмдэг илэрлээ", lines, row["id"])


def _vuln_risk_values(conn, form, row):
    cfg = vuln_risk_config(conn)
    errors = {}
    impacts = []
    for i in range(1, 9):
        raw = _vf(form, f"impact_{i}", 2)
        if raw:
            if raw.isdigit() and 1 <= int(raw) <= 5:
                impacts.append(int(raw))
            else:
                errors[f"impact_{i}"] = "1–5"
                impacts.append(None)
        else:
            impacts.append(None)
    lk_raw = _vf(form, "ra_likelihood", 2)
    likelihood = int(lk_raw) if lk_raw.isdigit() and 1 <= int(lk_raw) <= 5 else None
    if lk_raw and likelihood is None:
        errors["ra_likelihood"] = "1–5"
    complete = all(v is not None for v in impacts) and likelihood is not None
    impact = max(impacts) if complete else None
    score = impact * likelihood if complete else None
    values = {
        "ra_threat": _vf(form, "ra_threat", 5000) if "ra_threat" in form else (row["ra_threat"] or ""),
        "ra_impacts": json.dumps(impacts) if any(v is not None for v in impacts) else "",
        "ra_impact": impact, "ra_likelihood": likelihood, "ra_score": score,
        "ra_level": vuln_risk_level(score, cfg),
        "ra_decision_note": _vf(form, "ra_decision_note", 5000) if "ra_decision_note" in form else (row["ra_decision_note"] or ""),
    }
    return values, errors, complete


def vuln_api_action(conn, user, row, form):
    action = _vf(form, "action", 40)
    if action not in VULN_ACTIONS:
        return 400, {"error": "Үйлдэл буруу байна."}
    status = row["status"] or "new"
    if status not in VULN_ACTIONS[action][0]:
        return 409, {"error": f"«{VULN_STATUS_LABELS.get(status, status)}» төлөвт энэ үйлдлийг хийх боломжгүй. Хуудсаа дахин ачаална уу."}
    if action not in vuln_available_actions(user, row):
        return 403, {"error": "Энэ үйлдлийг хийх эрх танд алга."}
    ts = now_utc().isoformat()
    today = _vuln_today()
    note = _vf(form, "note", 5000)
    label = VULN_ACTIONS[action][2]
    event = _VULN_ACTION_EVENTS.get(action, "")
    after = []  # notifications sent after commit

    if action == "return":
        if not note:
            return _vuln_fail({"note": "Юуг засах шаардлагатайг бичнэ үү."})
        _vuln_apply(conn, user, row, {"status": "returned"}, note, audit_label=label)
        creator = _vuln_user_by_id(conn, row["created_by"])
        after.append(lambda: _vuln_notify([creator], f"[Эмзэг байдал] {_vuln_ref(row)} засварлуулахаар буцаалаа", [
            f"{_vuln_user_label(user)} таны бүртгэсэн эмзэг байдлыг мэдээлэл дутуу гэж буцаалаа.", ""]
            + _vuln_record_lines(row) + ["", "Тайлбар:", note], row["id"]))
        msg = "Бүртгэлийг InfoSec-д буцаалаа."

    elif action == "resubmit":
        _vuln_apply(conn, user, row, {"status": "new"}, note, audit_label=label)
        if row["reviewer_id"]:
            reviewer = _vuln_user_by_id(conn, row["reviewer_id"])
            after.append(lambda: _vuln_notify_reviewer(conn, user, reviewer, [row["id"]], resubmitted=True))
            msg = "Дахин илгээж, хариуцагчид мэдэгдлээ."
        else:
            after.append(lambda: _vuln_notify_receivers(conn, user, row["id"], resubmitted=True))
            msg = "Дахин илгээж, хүлээн авагчид мэдэгдлээ."

    elif action in ("save_assessment", "submit_assessment"):
        values, errors = _vuln_assessment_values(form, row)
        sec2, sec2_errors = _vuln_section2_values(form, row)
        values.update(sec2)
        errors.update(sec2_errors)
        submitting = action == "submit_assessment"
        custom, cerrors = _vuln_custom_parse(conn, "engineer", form, row, submitting)
        errors.update(cerrors)
        values["vuln_custom"] = json.dumps(custom, ensure_ascii=False)
        if submitting:
            eng = vuln_form_schema(conn, "engineer")  # required flags are managed by InfoSec in Settings → Маягт
            for fd in _vuln_form_fields(eng):
                f = fd["key"]
                if fd["builtin"] and not fd["block"] and fd["required"] and not fd["hidden"] and f in values:
                    if not values[f] and f not in errors:
                        errors[f] = "Заавал бөглөнө."
            has_evidence = conn.execute(
                "SELECT 1 FROM vulnerability_files WHERE vulnerability_id = ? AND category = 'as_evidence' AND deleted_at = ''",
                (row["id"],)).fetchone()
            if vuln_form_required(eng, "evidence_files") and not has_evidence:
                errors["evidence_files"] = "Нотолгооны файлыг хавсаргана уу."
        if errors:
            return _vuln_fail(errors)
        notify = _vuln_flag_incident(conn, user, row, values)
        if notify:
            after.append(notify)
        if action == "save_assessment":
            if (row["status"] or "") == "assigned":
                values["status"] = "under_assessment"  # first draft saved: work has started
            _vuln_apply(conn, user, row, values, audit_label="Хөрөнгө ба хариуцлага, үнэлгээ хадгалав")
            msg = "Хадгалагдлаа."
        else:
            # Inspection date = submission time (recorded automatically). InfoSec now decides whether the asset is affected.
            values.update(status="risk_assessment", as_submitted_at=ts, ra_due=vuln_ra_due(row["severity"]), ra_decision="")
            _vuln_apply(conn, user, row, values, note or values["as_conclusion"], event,
                        audit_label="Хөрөнгө ба хариуцлага, үнэлгээ илгээв — InfoSec эрсдэлийн үнэлгээ хийнэ")
            infosec = _vuln_role_users(conn, "infosec")
            after.append(lambda: _vuln_notify(infosec, f"[Эмзэг байдал] {_vuln_ref(row)} эрсдэлийн үнэлгээ хийх", [
                f"{_vuln_user_label(user)} хөрөнгө ба хариуцлагын мэдээлэл, үнэлгээгээ илгээлээ.",
                "Хөрөнгөд нөлөөлсөн эсэхийг тодорхойлж, эрсдэлийн үнэлгээ хийнэ үү.", ""]
                + _vuln_record_lines(_vuln_reload(conn, row)), row["id"]))
            msg = "Илгээгдлээ. InfoSec хөрөнгөд нөлөөлсөн эсэхийг тодорхойлж, эрсдэлийн үнэлгээ хийнэ."

    elif action == "risk_assess" and (row["as_affected"] or "") != "yes" and _vf(form, "as_affected", 20) == "no":
        # Not affected: explanation required (evidence goes to «Нотлох баримт»); close without a risk assessment.
        ia_note = _vf(form, "ia_note", 5000)
        if not ia_note:
            return _vuln_fail({"ia_note": "Нөлөөлөөгүй гэх тайлбарыг бичнэ үү."})
        values = {"as_affected": "no", "ia_note": ia_note, "ia_decided_by": user["id"], "ia_decided_at": ts,
                  "status": "not_affected", "closed_at": ts, "risk_status": "not_affected", "ra_decision": ""}
        _vuln_apply(conn, user, row, values, ia_note, "impact_decided", audit_label="Хөрөнгөд нөлөөлөөгүй — хаав")
        after.append(lambda: _vuln_notify_closed(conn, user, _vuln_reload(conn, row), "not_affected"))
        msg = "Хөрөнгөд нөлөөлөөгүй тул бүртгэл хаагдлаа."

    elif action == "risk_assess":
        values, errors, complete = _vuln_risk_values(conn, form, row)
        affected_extra = {}
        if (row["as_affected"] or "") != "yes":
            affected = _vf(form, "as_affected", 20)
            if affected == "yes":
                affected_extra = {"as_affected": "yes", "ia_note": _vf(form, "ia_note", 5000),
                                  "ia_decided_by": user["id"], "ia_decided_at": ts}
            elif _vf(form, "ra_decision", 20):
                errors["as_affected"] = "Хөрөнгөд нөлөөлсөн эсэхийг сонгоно уу."
        decision = _vf(form, "ra_decision", 20)
        if decision not in VULN_DECISION_LABELS:
            errors["ra_decision"] = "Шийдвэр буруу."
        risk_form = vuln_form_schema(conn, "risk")
        custom, cerrors = _vuln_custom_parse(conn, "risk", form, row, bool(decision))
        errors.update(cerrors)
        values["vuln_custom"] = json.dumps(custom, ensure_ascii=False)
        if decision:
            if not values["ra_threat"] and vuln_form_required(risk_form, "ra_threat"):
                errors["ra_threat"] = "Аюулыг тодорхойлно уу."
            if not values["ra_decision_note"] and vuln_form_required(risk_form, "ra_decision_note"):
                errors["ra_decision_note"] = "Шийдвэрийн үндэслэлийг бичнэ үү."
            for i in range(1, 9):
                if f"impact_{i}" not in errors and not _vf(form, f"impact_{i}", 2):
                    errors[f"impact_{i}"] = "1–5"
            if values["ra_likelihood"] is None and "ra_likelihood" not in errors:
                errors["ra_likelihood"] = "Магадлал сонгоно уу."
        if decision in ("transfer", "accept", "avoid") and not values["ra_decision_note"]:
            errors["ra_decision_note"] = "Шийдвэрийн үндэслэлийг бичнэ үү."
        until = _vf(form, "risk_accept_until", 10)
        if decision == "accept":
            if not until or not _valid_iso_date(until):
                errors["risk_accept_until"] = "Хүлээн зөвшөөрөх хугацааг оруулна уу."
            elif until <= today:
                errors["risk_accept_until"] = "Ирээдүйн огноо байх ёстой."
        if decision == "transfer":
            nfiles = conn.execute("SELECT COUNT(*) FROM vulnerability_files WHERE vulnerability_id = ? AND deleted_at = ''",
                                  (row["id"],)).fetchone()[0]
            if not nfiles:
                errors["ra_decision"] = "Шилжүүлсэн нотлох баримтыг (гэрээ, даатгал, нийлүүлэгчийн баталгаа) эхлээд хавсаргана уу."
        if errors:
            return _vuln_fail(errors)
        values.update(ra_assessed_by=user["id"], ra_assessed_at=ts, ra_decision=decision)
        values.update(affected_extra)
        if not decision:
            _vuln_apply(conn, user, row, values, audit_label="Эрсдэлийн үнэлгээ (ноорог) хадгалав")
            msg = "Эрсдэлийн үнэлгээ хадгалагдлаа."
        else:
            dnote = values["ra_decision_note"]
            summary = (f"Эрсдэл: {VULN_RISK_LEVEL_LABELS[values['ra_level']]} (нөлөөлөл {values['ra_impact']} × магадлал "
                       f"{values['ra_likelihood']} = {values['ra_score']}). Шийдвэр: {VULN_DECISION_LABELS[decision]}."
                       + (f"\n{dnote}" if dnote else ""))
            assignee = _vuln_user_by_id(conn, row["assignee_id"])
            if decision == "mitigate":
                values["status"] = "remediation"
                after.append(lambda: _vuln_notify([assignee], f"[Эмзэг байдал] {_vuln_ref(row)} засвар хийх", [
                    "Эрсдэлийн үнэлгээгээр эрсдэлийг бууруулах (засварлах) шийдвэр гарлаа. Засварын төлөвлөгөөгөө оруулна уу.", ""]
                    + _vuln_record_lines(row) + [f"Засварлах хугацаа (SLA): {row['due_date'] or '—'}"], row["id"]))
            elif decision == "transfer":
                values.update(status="transferred", closed_at=ts, risk_status="transferred")
                after.append(lambda: _vuln_notify_closed(conn, user, _vuln_reload(conn, row), "transferred"))
            elif decision == "avoid":
                values["status"] = "avoidance"
                after.append(lambda: _vuln_notify([assignee], f"[Эмзэг байдал] {_vuln_ref(row)} систем зогсоох", [
                    "Эрсдэлээс зайлсхийх шийдвэр гарлаа: системийг зогсоох / үйлчилгээг зогсоож, баталгаажуулна уу.", ""]
                    + _vuln_record_lines(row) + ["", dnote], row["id"]))
            else:  # accept → CTO approval
                values.update(status="pending_cto", risk_accept_reason=dnote, risk_accept_until=until,
                              risk_accept_requested_by=user["id"], risk_accept_approver_id=None)
                ctos = _vuln_role_users(conn, "cto")
                after.append(lambda: _vuln_notify(ctos, f"[Эмзэг байдал] {_vuln_ref(row)} эрсдэл хүлээн зөвшөөрөх хүсэлт", [
                    f"{_vuln_user_label(user)} эрсдэлийг {until} хүртэл хүлээн зөвшөөрөх зөвшөөрөл хүсч байна.", ""]
                    + _vuln_record_lines(row) + ["", summary], row["id"]))
            _vuln_apply(conn, user, row, values, summary, event, audit_label=f"Эрсдэлийн шийдвэр: {VULN_DECISION_LABELS[decision]}")
            msg = {"mitigate": "Засварын шатанд шилжлээ.", "transfer": "Эрсдэлийг шилжүүлж, бүртгэл хаагдлаа.",
                   "avoid": "Инженерт систем зогсоох даалгавар өглөө.", "accept": "CTO-ийн зөвшөөрөлд илгээлээ."}[decision]

    elif action == "cto_approve":
        until = _vf(form, "risk_accept_until", 10) or row["risk_accept_until"]
        if not _valid_iso_date(until) or until <= today:
            return _vuln_fail({"risk_accept_until": "Ирээдүйн огноо байх ёстой."})
        _vuln_apply(conn, user, row, {"status": "accepted", "risk_accept_approver_id": user["id"], "risk_accept_until": until,
                                      "risk_status": "accepted"},
                    f"CTO зөвшөөрөв: {until} хүртэл." + (f"\n{note}" if note else ""), event, audit_label=label)
        req = _vuln_user_by_id(conn, row["risk_accept_requested_by"])
        after.append(lambda: _vuln_notify([req], f"[Эмзэг байдал] {_vuln_ref(row)} эрсдэлийг CTO зөвшөөрлөө", [
            f"{_vuln_user_label(user)} эрсдэлийг {until} хүртэл хүлээн зөвшөөрлөө. Хугацаа дуусахад дахин үнэлгээнд автоматаар буцна.", ""]
            + _vuln_record_lines(row) + ([note] if note else []), row["id"]))
        msg = "Эрсдэлийг хүлээн зөвшөөрлөө."

    elif action == "cto_reject":
        if not note:
            return _vuln_fail({"note": "Татгалзсан шалтгааныг бичнэ үү."})
        _vuln_apply(conn, user, row, {"status": "risk_assessment", "ra_decision": "", "ra_due": vuln_ra_due(row["severity"])},
                    note, event, audit_label=label)
        req = _vuln_user_by_id(conn, row["risk_accept_requested_by"])
        after.append(lambda: _vuln_notify([req] + list(_vuln_role_users(conn, "infosec")),
                                          f"[Эмзэг байдал] {_vuln_ref(row)} эрсдэл хүлээн зөвшөөрөхөөс татгалзлаа", [
            f"{_vuln_user_label(user)} эрсдэл хүлээн зөвшөөрөх хүсэлтийг татгалзлаа. Эрсдэлийг дахин үнэлнэ үү.", ""]
            + _vuln_record_lines(row) + ["", "Шалтгаан:", note], row["id"]))
        msg = "Татгалзаж, эрсдэлийн үнэлгээнд буцаалаа."

    elif action == "avoid_confirm":
        text = _vf(form, "avoid_note", 5000)
        if not text:
            return _vuln_fail({"avoid_note": "Зогсоосон систем / үйлчилгээ, хийсэн ажлыг бичнэ үү."})
        _vuln_apply(conn, user, row, {"avoid_note": text, "avoid_confirmed_at": ts}, text, event, audit_label=label)
        infosec = _vuln_role_users(conn, "infosec")
        after.append(lambda: _vuln_notify(infosec, f"[Эмзэг байдал] {_vuln_ref(row)} систем зогсоосон — хянах", [
            f"{_vuln_user_label(user)} системийг зогсоосноо баталгаажууллаа. Хянаж, бүртгэлийг хаана уу.", ""]
            + _vuln_record_lines(row) + ["", text], row["id"]))
        msg = "Баталгаажуулж, InfoSec-д мэдэгдлээ."

    elif action == "avoid_close":
        comment = _vf(form, "closure_comment", 10000)
        if not comment:
            return _vuln_fail({"closure_comment": "Хаалтын тайлбар бичнэ үү."})
        _vuln_apply(conn, user, row, {"status": "closed", "closure_comment": comment, "closed_at": ts, "risk_status": "avoided",
                                      "residual_risk": _vf(form, "residual_risk", 5000)}, comment, event, audit_label=label)
        after.append(lambda: _vuln_notify_closed(conn, user, _vuln_reload(conn, row), "closed"))
        msg = "Бүртгэл хаагдлаа."

    elif action in ("save_remediation", "submit_fix", "submit_temp"):
        values, errors = {}, {}
        for f in ("rm_plan", "rm_actions", "rm_change_ref"):
            values[f] = _vf(form, f, 300 if f == "rm_change_ref" else 10000) if f in form else (row[f] or "")
        values["rm_target_date"] = _vf(form, "rm_target_date", 10) if "rm_target_date" in form else (row["rm_target_date"] or "")
        if values["rm_target_date"] and not _valid_iso_date(values["rm_target_date"]):
            errors["rm_target_date"] = "Огноо буруу."
        if action == "submit_fix":
            for f in ("rm_plan", "rm_actions", "rm_target_date", "rm_change_ref"):
                if not values[f] and f not in errors:
                    errors[f] = "Заавал бөглөнө."
            rem = _vf(form, "remediated_date", 10) or today
            if not _valid_iso_date(rem) or rem > today:
                errors["remediated_date"] = "Зассан огноо буруу."
            values.update(remediated_date=rem, rm_fix_type="fixed", status="verification")
        if action == "submit_temp":
            values["tm_controls"] = _vf(form, "tm_controls", 10000)
            values["tm_until"] = _vf(form, "tm_until", 10)
            if not values["tm_controls"]:
                errors["tm_controls"] = "Нөхөх хяналтыг тайлбарлана уу."
            if not _valid_iso_date(values["tm_until"]):
                errors["tm_until"] = "Хүчинтэй хугацааг оруулна уу."
            elif values["tm_until"] <= today:
                errors["tm_until"] = "Ирээдүйн огноо байх ёстой."
            values.update(rm_fix_type="temp", status="verification")
        if errors:
            return _vuln_fail(errors)
        if action == "save_remediation":
            _vuln_apply(conn, user, row, values, audit_label="Засварын төлөвлөгөө хадгалав")
            msg = "Засварын төлөвлөгөө хадгалагдлаа."
        else:
            _vuln_apply(conn, user, row, values, note, event, audit_label=label)
            infosec = _vuln_role_users(conn, "infosec")
            kind = "засвар хийснээ" if action == "submit_fix" else "түр хамгаалалт хэрэгжүүлснээ"
            after.append(lambda: _vuln_notify(infosec, f"[Эмзэг байдал] {_vuln_ref(row)} баталгаажуулах", [
                f"{_vuln_user_label(user)} {kind} мэдэгдлээ. Дахин скан хийх, хувилбар шалгах замаар баталгаажуулна уу.", ""]
                + _vuln_record_lines(row), row["id"]))
            msg = "Баталгаажуулалтад илгээлээ."

    elif action == "cannot_remediate":
        if not note:
            return _vuln_fail({"note": "Засварлах боломжгүй шалтгааныг бичнэ үү."})
        _vuln_apply(conn, user, row, {"status": "risk_assessment", "ra_decision": "", "ra_due": vuln_ra_due(row["severity"])},
                    note, event, audit_label=label)
        infosec = _vuln_role_users(conn, "infosec")
        after.append(lambda: _vuln_notify(infosec, f"[Эмзэг байдал] {_vuln_ref(row)} засварлах боломжгүй — дахин үнэлэх", [
            f"{_vuln_user_label(user)} засварлах боломжгүй гэж мэдэгдлээ. Эрсдэлийг дахин үнэлнэ үү.", ""]
            + _vuln_record_lines(row) + ["", "Шалтгаан:", note], row["id"]))
        msg = "Эрсдэлийн үнэлгээнд буцаалаа."

    elif action == "verify_fail":
        vf = _vf(form, "vf_note", 10000)
        if not vf:
            return _vuln_fail({"vf_note": "Юу засагдаагүйг тайлбарлана уу."})
        _vuln_apply(conn, user, row, {"status": "remediation", "vf_note": vf, "rm_fix_type": ""}, vf, event, audit_label=label)
        assignee = _vuln_user_by_id(conn, row["assignee_id"])
        after.append(lambda: _vuln_notify([assignee], f"[Эмзэг байдал] {_vuln_ref(row)} засагдаагүй байна", [
            f"{_vuln_user_label(user)} баталгаажуулалтаар эмзэг байдал засагдаагүй гэж буцаалаа.", ""]
            + _vuln_record_lines(row) + ["", "Тайлбар:", vf], row["id"]))
        msg = "Засварын шат руу буцаалаа."

    elif action == "verify_temp":
        if not row["tm_until"] or row["tm_until"] <= today:
            return 409, {"error": "Түр хамгаалалтын хүчинтэй хугацаа дууссан байна. «Засагдаагүй — буцаах»-ыг ашиглана уу."}
        vf = _vf(form, "vf_note", 10000)
        _vuln_apply(conn, user, row, {"status": "temp_mitigation", "vf_note": vf or row["vf_note"]}, vf, event, audit_label=label)
        msg = f"Түр хамгаалалт {row['tm_until']} хүртэл хүчинтэй. Хугацаа дуусахад засвар руу автоматаар буцна."

    elif action == "close":
        errors = {}
        vf = _vf(form, "vf_note", 10000)
        comment = _vf(form, "closure_comment", 10000)
        residual = _vf(form, "residual_risk", 5000)
        rstatus = _vf(form, "risk_status", 20)
        if not vf:
            errors["vf_note"] = "Дахин скан / хувилбарын шалгалтын үр дүнг бичнэ үү."
        if not comment:
            errors["closure_comment"] = "Хаалтын тайлбар бичнэ үү."
        if not residual:
            errors["residual_risk"] = "Үлдэгдэл эрсдэлийг бичнэ үү (байхгүй бол «Байхгүй»)."
        if rstatus not in ("mitigated", "residual"):
            errors["risk_status"] = "Эрсдэлийн төлөвийг сонгоно уу."
        if errors:
            return _vuln_fail(errors)
        _vuln_apply(conn, user, row, {"status": "closed", "vf_note": vf, "closure_comment": comment, "residual_risk": residual,
                                      "risk_status": rstatus, "closed_at": ts}, comment, event, audit_label=label)
        after.append(lambda: _vuln_notify_closed(conn, user, _vuln_reload(conn, row), "closed"))
        msg = "Баталгаажуулж, бүртгэлийг хаалаа. хүлээн авагч, CTO-д мэдэгдлээ."

    elif action == "temp_resume":
        if not note:
            return _vuln_fail({"note": "Шалтгааныг бичнэ үү (жишээ: patch гарсан)."})
        _vuln_apply(conn, user, row, {"status": "remediation", "rm_fix_type": ""}, note, audit_label=label)
        msg = "Засварын шат руу шилжлээ."
    else:
        return 400, {"error": "Үйлдэл буруу байна."}

    conn.commit()
    for fn in after:
        try:
            fn()
        except Exception:  # a failed e-mail must never undo a committed workflow step
            traceback.print_exc()
    body = {"id": row["id"], "message": msg}
    if action == "submit_assessment":
        body["submittedAt"] = ts  # inspection date, shown in the engineer's confirmation
    return 200, body


_vuln_last_sweep = [0.0]


def vuln_expire_sweep(conn, force=False):
    """Accepted risk past its period → back to Risk Assessment; expired temporary mitigation → back to Remediation."""
    if not force and time.time() - _vuln_last_sweep[0] < 60:
        return
    _vuln_last_sweep[0] = time.time()
    today = _vuln_today()
    rows = conn.execute(
        f"""{_VULN_SELECT_SQL} WHERE v.deleted_at = '' AND (
              (v.status = 'accepted' AND v.risk_accept_until <> '' AND v.risk_accept_until < ?)
              OR (v.status = 'temp_mitigation' AND v.tm_until <> '' AND v.tm_until < ?))""", (today, today)).fetchall()
    after = []
    for r in rows:
        if r["status"] == "accepted":
            _vuln_apply(conn, None, r, {"status": "risk_assessment", "ra_decision": "", "risk_status": "",
                                        "ra_due": vuln_ra_due(r["severity"])},
                        f"Эрсдэл хүлээн зөвшөөрсөн хугацаа ({r['risk_accept_until']}) дууссан тул дахин үнэлнэ.", "accept_expired",
                        audit_label="Эрсдэл хүлээн зөвшөөрсөн хугацаа дууссан")
            users = list(_vuln_role_users(conn, "infosec"))
            after.append((users, r, "эрсдэл хүлээн зөвшөөрсөн хугацаа дууссан — дахин үнэлэх"))
        else:
            _vuln_apply(conn, None, r, {"status": "remediation", "rm_fix_type": ""},
                        f"Түр хамгаалалтын хугацаа ({r['tm_until']}) дууссан тул засвар руу буцлаа.", "temp_expired",
                        audit_label="Түр хамгаалалтын хугацаа дууссан")
            users = [_vuln_user_by_id(conn, r["assignee_id"])] + list(_vuln_role_users(conn, "infosec"))
            after.append((users, r, "түр хамгаалалтын хугацаа дууссан — засвар хийх"))
    if rows:
        conn.commit()
    for users, r, what in after:
        _vuln_notify(users, f"[Эмзэг байдал] {_vuln_ref(r)} {what}", _vuln_record_lines(r), r["id"])


def _vuln_can_upload(user, row):
    return (vuln_can_manage(user) or _vuln_is_assignee(user, row) or vuln_can_assign_record(user, row)
            or vuln_is_cto(user))


def _vuln_can_delete_file(user, row, file_row):
    if vuln_can_manage(user):
        return True
    return _vuln_is_assignee(user, row) and file_row["uploaded_by"] == user["id"]


def vuln_api_detail(conn, user, row):
    today = now_utc().date()
    soon_days = vuln_soon_days(conn)
    item = _vuln_list_item(row, today, soon_days)
    item.update({
        "source": row["source"], "sourceUrl": row["source_url"],
        "published": row["published_date"], "reported": row["reported_date"],
        "description": row["description"], "scope": row["scope"], "verification": row["verification_method"],
        "recommendation": row["recommendation"], "threatTrend": row["threat_trend"],
        "impact": row["impact"], "riskJustification": row["risk_justification"],
        "remediationNotes": row["remediation_notes"], "remediatedDate": row["remediated_date"],
        "remediationDays": row["remediation_days"], "closedAt": row["closed_at"],
        "custom": vuln_custom_values(row),
        "ownerCustodian": row["owner_custodian"], "inUse": row["in_use"], "affectedAsset": row["affected_asset"],
        "envPresent": row["env_present"], "compromiseSigns": row["compromise_signs"],
        "impactDecision": {"affected": row["as_affected"], "note": row["ia_note"], "decidedAt": row["ia_decided_at"],
                   "decidedBy": _vuln_user_label(_vuln_user_by_id(conn, row["ia_decided_by"])) if row["ia_decided_by"] else ""},
        "riskAccept": {
            "reason": row["risk_accept_reason"], "until": row["risk_accept_until"],
            "approver": row["risk_approver_name"] or "", "approverId": row["risk_accept_approver_id"],
        } if row["risk_accept_reason"] else None,
        "createdBy": row["created_by_name"] or "", "createdAt": row["created_at"],
        "reviewer": {"id": row["reviewer_id"], "name": row["reviewer_name"] or ""} if row["reviewer_id"] else None, "updatedAt": row["updated_at"],
        "assetInfo": {
            "id": row["asset_id"], "name": row["asset_name"] or "", "type": row["asset_type"] or "",
            "owner": row["asset_owner"] or "", "custodian": row["asset_custodian"] or "",
            "location": row["asset_location"] or "", "category": row["asset_category"] or "",
            "dept": row["asset_department_name"] or "",
        } if row["asset_id"] else ({"id": None, "name": row["asset_name"], "type": "", "owner": "", "custodian": "",
                                    "location": "", "category": "", "dept": ""} if row["asset_name"] else None),
    })
    files = conn.execute(
        f"""SELECT f.*, {_uname_sql('u')} AS uploader FROM vulnerability_files f
            LEFT JOIN users u ON u.id = f.uploaded_by
            WHERE f.vulnerability_id = ? AND f.deleted_at = '' ORDER BY f.id DESC""", (row["id"],)).fetchall()
    item["files"] = [{
        "id": f["id"], "name": f["original_name"], "size": f["size"], "uploader": f["uploader"] or "",
        "uploadedAt": f["uploaded_at"], "canDelete": _vuln_can_delete_file(user, row, f), "category": f["category"],
    } for f in files]
    custom_labels = vuln_custom_labels(conn)
    item["activity"] = [{
        "id": a["id"], "actor": a["actor_name"], "action": a["action"], "field": a["field"],
        "fieldLabel": VULN_FIELD_LABELS.get(a["field"]) or custom_labels.get(a["field"])
                      or ("Нэмэлт талбар (устгасан)" if (a["field"] or "").startswith("cf_") else a["field"]),
        "old": a["old_value"], "new": a["new_value"], "note": a["note"], "at": a["created_at"],
    } for a in conn.execute(
        "SELECT * FROM vulnerability_activity WHERE vulnerability_id = ? ORDER BY id DESC", (row["id"],))]
    try:
        impacts = json.loads(row["ra_impacts"]) if row["ra_impacts"] else []
    except ValueError:
        impacts = []
    item.update({
        "groupId": row["group_id"],
        "assessment": {k: row[k] for k in _VULN_ASSESS_TEXT + tuple(_VULN_ASSESS_CHOICE)} | {"submittedAt": row["as_submitted_at"]},
        "risk": {
            "threat": row["ra_threat"], "impacts": impacts, "impact": row["ra_impact"], "likelihood": row["ra_likelihood"],
            "score": row["ra_score"], "level": row["ra_level"], "due": row["ra_due"], "decision": row["ra_decision"],
            "decisionNote": row["ra_decision_note"], "assessedAt": row["ra_assessed_at"],
            "assessedBy": _vuln_user_label(_vuln_user_by_id(conn, row["ra_assessed_by"])),
            "dueKind": ("overdue" if row["ra_due"] and row["ra_due"] < today.isoformat() else "ontrack")
            if (row["status"] or "") == "risk_assessment" and row["ra_due"] else "",
        },
        "remediation": {
            "plan": row["rm_plan"], "actions": row["rm_actions"], "targetDate": row["rm_target_date"], "changeRef": row["rm_change_ref"],
            "fixType": row["rm_fix_type"], "tmControls": row["tm_controls"], "tmUntil": row["tm_until"],
            "avoidNote": row["avoid_note"], "avoidConfirmedAt": row["avoid_confirmed_at"],
        },
        "closure": {"vfNote": row["vf_note"], "comment": row["closure_comment"], "residual": row["residual_risk"],
                    "riskStatus": row["risk_status"], "riskStatusLabel": VULN_RISK_STATUS_LABELS.get(row["risk_status"] or "", "")},
        "riskConfig": vuln_risk_config(conn),
    })
    if item["riskAccept"] is not None:
        item["riskAccept"]["requestedBy"] = _vuln_user_label(_vuln_user_by_id(conn, row["risk_accept_requested_by"]))
    elif row["risk_accept_until"]:
        item["riskAccept"] = {"reason": "", "until": row["risk_accept_until"], "approver": row["risk_approver_name"] or "",
                              "approverId": row["risk_accept_approver_id"], "requestedBy": ""}
    scope_sql, scope_args = _vuln_scope(user)
    item["group"] = [{
        "id": g["id"], "ref": _vuln_ref(g), "asset": g["asset_name"] or "", "status": g["status"],
        "assignee": g["assignee_name"] or "",
    } for g in conn.execute(f"{_VULN_SELECT_SQL} WHERE v.group_id = ? AND v.id <> ? AND {scope_sql} ORDER BY v.id",
                            [row["group_id"] or row["id"], row["id"]] + scope_args)]
    item["perms"] = {
        "edit": vuln_can_edit_record(user, row),
        "upload": _vuln_can_upload(user, row),
        "delete": vuln_can_delete(user),
        "actions": vuln_available_actions(user, row),
        "assign": vuln_can_assign_record(user, row) and (row["status"] or "new") in VULN_ASSIGNABLE_STATUSES,
        "comment": True,
        "isAssignee": _vuln_is_assignee(user, row),
    }
    item["actionLabels"] = {k: v[2] for k, v in VULN_ACTIONS.items()}
    return item


def _vuln_display(conn, field, value):
    """Human-readable value for the activity log."""
    if value is None or value == "":
        return ""
    if field == "asset_id":
        r = conn.execute("SELECT asset_name FROM assets WHERE id = ?", (value,)).fetchone()
        return f"{r['asset_name']} (#{value})" if r else f"#{value}"
    if field == "department_id":
        r = conn.execute("SELECT name FROM departments WHERE id = ?", (value,)).fetchone()
        return r["name"] if r else f"#{value}"
    if field in ("assignee_id",):
        return _vuln_user_label(conn.execute("SELECT * FROM users WHERE id = ?", (value,)).fetchone()) or f"#{value}"
    if field == "cvss_score":
        return f"{float(value):.1f}"
    if field == "severity":
        return VULN_SEV_LABELS.get(str(value).lower(), value)
    if field == "env_present":
        return VULN_ENV_PRESENT_LABELS.get(value, value)
    if field == "compromise_signs":
        return VULN_COMPROMISE_LABELS.get(value, value)
    if field in ("as_internet_facing", "as_patch_available", "as_affected", "as_exploited", "in_use"):
        return VULN_YN_LABELS.get(value, value)
    if field == "ra_decision":
        return VULN_DECISION_LABELS.get(value, value)
    if field == "ra_level":
        return VULN_RISK_LEVEL_LABELS.get(value, value)
    if field == "risk_status":
        return VULN_RISK_STATUS_LABELS.get(value, value)
    if field == "ra_impacts":
        try:
            return " · ".join(f"Н{i}={v if v is not None else '—'}" for i, v in enumerate(json.loads(value), 1))
        except (ValueError, TypeError):
            return str(value)
    return str(value)


def _vuln_same(a, b):
    if a in (None, "") and b in (None, ""):
        return True
    if isinstance(a, float) or isinstance(b, float):
        try:
            return a is not None and b is not None and abs(float(a) - float(b)) < 1e-9
        except (TypeError, ValueError):
            return False
    return a == b


def vuln_api_create(conn, user, form):
    """Step 1 (InfoSec): register a vulnerability with its CVSS and every potentially affected asset.

    One finding is created per asset (same registration group). The registrant picks the responsible person in the
    «Хүлээн авагч сонгох» window (active users with the «Хүлээн авагч» role); every finding goes to that person instead of the Recipient
    (status stays New). For these records the responsible person has exactly the Recipient's duties: review, return,
    assign the engineer. Everything after that is the unchanged workflow.
    """
    if not vuln_can_manage(user):
        return 403, {"error": "Эрх хүрэлцэхгүй байна."}
    values, errors = _vuln_validate(conn, user, form)
    raw_reviewer = (form.get("reviewer_id") or "").strip()
    reviewer = conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1 AND " + _VULN_HAS_ROLE_SQL.format(col="vuln_role"),
                            (int(raw_reviewer), "receiver")).fetchone() if raw_reviewer.isdigit() else None
    if not reviewer:
        errors["reviewer_id"] = "«Хүлээн авагч» эрхтэй хэрэглэгчийг сонгоно уу."
    custom, cerrors = _vuln_custom_parse(conn, "register", form, None, True)
    errors.update(cerrors)
    values["vuln_custom"] = json.dumps(custom, ensure_ascii=False)
    if values["cvss_score"] is None and "cvss_score" not in errors:
        errors["cvss_score"] = "CVSS оноо заавал оруулна (түвшин, SLA үүнээс тооцоологдоно)."
    extra_ids = []
    for tok in (form.get("extra_asset_ids") or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if not tok.isdigit() or not conn.execute("SELECT 1 FROM assets WHERE id = ?", (int(tok),)).fetchone():
            errors["extra_asset_ids"] = "Нэмэлт хөрөнгийн жагсаалтад олдохгүй хөрөнгө байна."
            break
        if int(tok) != values["asset_id"] and int(tok) not in extra_ids:
            extra_ids.append(int(tok))
    if len(extra_ids) > 50:
        errors["extra_asset_ids"] = "Нэг удаад 50-аас ихгүй хөрөнгө."
    if errors:
        msg = errors["reviewer_id"] if list(errors) == ["reviewer_id"] else "Талбаруудыг шалгана уу."
        return 422, {"error": msg, "fields": errors}
    vuln_id = _vuln_insert(conn, user, values)
    ids = [vuln_id]
    for aid in extra_ids:
        a = conn.execute("SELECT id, department_id, owner, custodian FROM assets WHERE id = ?", (aid,)).fetchone()
        o, c = (a["owner"] or "").strip(), (a["custodian"] or "").strip()
        ids.append(_vuln_insert(conn, user, dict(values, asset_id=aid, department_id=a["department_id"],
                                                 owner_custodian=f"{o} / {c}" if o and c and o != c else (o or c)),
                                group_id=vuln_id))
    name = _vuln_user_label(reviewer)
    for i in ids:
        conn.execute("UPDATE vulnerabilities SET reviewer_id = ? WHERE id = ?", (reviewer["id"], i))
        _vuln_log(conn, i, user, "updated", "reviewer_id", "", name)
    conn.commit()
    _vuln_notify_reviewer(conn, user, reviewer, ids)
    n = f" ({len(ids)} хөрөнгө)" if len(ids) > 1 else ""
    return 200, {"id": vuln_id, "ids": ids,
                 "message": f"Эмзэг байдал бүртгэгдэж{n}, хариуцагч {name}-д мэдэгдэл илгээлээ."}


def _vuln_notify_reviewer(conn, actor, reviewer, ids, resubmitted=False):
    """Mail the responsible person (and anyone substituting for them today) that records await review."""
    rows = [conn.execute(f"{_VULN_SELECT_SQL} WHERE v.id = ?", (i,)).fetchone() for i in ids]
    row = rows[0]
    today = _vuln_today()
    subs = conn.execute(
        """SELECT u.* FROM vuln_substitutes s JOIN users u ON u.id = s.substitute_id
           WHERE s.principal_id = ? AND s.revoked_at = '' AND u.is_active = 1
           AND s.start_date <= ? AND s.end_date >= ?""", (reviewer["id"], today, today)).fetchall()
    what = "засварлаж дахин илгээлээ" if resubmitted else "бүртгэж, таныг хариуцагчаар сонголоо"
    lines = [
        f"{_vuln_user_label(actor)} эмзэг байдал {what}.",
        "Хянаж, нөлөөлөх хөрөнгө бүрт засварлах инженер томилно уу (мэдээлэл дутуу бол буцаана).", "",
        f"{row['cve_id'] + ' — ' if row['cve_id'] else ''}{row['title']}",
        f"Түвшин: {VULN_SEV_LABELS.get((row['severity'] or '').lower(), row['severity'])}"
        + (f" (CVSS {row['cvss_score']:.1f})" if row["cvss_score"] is not None else ""),
        f"Засварлах хугацаа (SLA): {row['due_date'] or '—'}",
        "",
        "Нөлөөлөх хөрөнгө:",
    ] + [f"  • {_vuln_ref(r)} — {r['asset_name'] or '—'}" for r in rows]
    _vuln_notify([reviewer] + list(subs), f"[Эмзэг байдал] {_vuln_ref(row)} хянах хүсэлт", lines, row["id"])


def vuln_api_update(conn, user, row, form):
    is_manager = vuln_can_edit_record(user, row)  # registration details: only the InfoSec user who created it
    if not (is_manager or _vuln_is_assignee(user, row)):
        return 403, {"error": "Эрх хүрэлцэхгүй байна."}
    changes = {}
    if is_manager and form.get("scope_of_edit") != "remediation":
        values, errors = _vuln_validate(conn, user, form, existing=row)
        custom, cerrors = _vuln_custom_parse(conn, "register", form, row, True)
        errors.update(cerrors)
        if errors:
            return 422, {"error": "Талбаруудыг шалгана уу.", "fields": errors}
        for field in _VULN_MANAGER_FIELDS:
            if not _vuln_same(row[field], values[field]):
                changes[field] = values[field]
        if custom != vuln_custom_values(row):
            changes["vuln_custom"] = json.dumps(custom, ensure_ascii=False)
        if not _vuln_same(row["remediation_days"], values["remediation_days"]):
            changes["remediation_days"] = values["remediation_days"]
    # Remediation information: editable by managers and by the assignee.
    errors = {}
    notes = (form.get("remediation_notes") or "").strip()
    rem_date = (form.get("remediated_date") or "").strip()
    if "remediation_notes" in form:
        if len(notes) > _VULN_EXTRA_TEXT_LIMITS["remediation_notes"]:
            errors["remediation_notes"] = "Хэт урт байна."
        elif notes != (row["remediation_notes"] or ""):
            changes["remediation_notes"] = notes
    if "remediated_date" in form:
        if rem_date and not _valid_iso_date(rem_date):
            errors["remediated_date"] = "Огноо буруу форматтай байна."
        elif rem_date and rem_date > now_utc().date().isoformat():
            errors["remediated_date"] = "Ирээдүйн огноо байж болохгүй."
        elif rem_date != (row["remediated_date"] or ""):
            changes["remediated_date"] = rem_date
    if errors:
        return 422, {"error": "Талбаруудыг шалгана уу.", "fields": errors}
    if not changes:
        return 200, {"id": row["id"], "message": "Өөрчлөлт алга."}

    status = row["status"] or "new"
    new_status = status
    if "assignee_id" in changes:
        if changes["assignee_id"] and status == "new":
            new_status = "assigned"
        elif not changes["assignee_id"] and status == "assigned":
            new_status = "new"
    ts = now_utc().isoformat()
    cols = dict(changes, updated_at=ts, updated_by=user["id"])
    if new_status != status:
        cols["status"] = new_status
    conn.execute(
        "UPDATE vulnerabilities SET " + ", ".join(f"{c} = ?" for c in cols) + " WHERE id = ?",
        list(cols.values()) + [row["id"]],
    )
    for field, new in changes.items():
        if field == "remediation_days":
            continue
        if field == "vuln_custom":
            _vuln_custom_log(conn, row, user, vuln_custom_values(row), json.loads(new))
            continue
        _vuln_log(conn, row["id"], user, "updated", field,
                  _vuln_display(conn, field, row[field]), _vuln_display(conn, field, new))
    if new_status != status:
        _vuln_log(conn, row["id"], user, "status_changed", "status", status, new_status,
                  "Хариуцагч өөрчлөгдсөнтэй холбоотой автоматаар.")
    labels = ", ".join(("Нэмэлт талбар" if f == "vuln_custom" else VULN_FIELD_LABELS.get(f, f))
                       for f in changes if f != "remediation_days")
    record_audit(conn, user["id"], "update", "vulnerability", entity_id=row["id"],
                 department_id=row["department_id"], details=f"{_vuln_ref(row)} засварлав: {labels}")
    conn.commit()
    return 200, {"id": row["id"], "message": "Өөрчлөлт хадгалагдлаа."}


def vuln_api_assign(conn, user, row, form):
    """Recipient assigns the responsible engineer for the vulnerability's asset; New/Reopened become Assigned."""
    current = row["status"] or "new"
    if not vuln_can_assign_record(user, row):
        return 403, {"error": "Инженер томилох эрх зөвхөн тухайн бүртгэлийн хариуцагчид байна."
                     if row["reviewer_id"] else "Инженер томилох эрх зөвхөн хүлээн авагчид байна."}
    if current not in VULN_ASSIGNABLE_STATUSES:
        return 409, {"error": f"«{VULN_STATUS_LABELS[current]}» төлөвтэй бүртгэлд хариуцагч томилох боломжгүй."}
    raw = (form.get("assignee_id") or "").strip()
    note = (form.get("note") or "").strip()[:5000]
    engineer = conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1 AND " + _VULN_HAS_ROLE_SQL.format(col="vuln_role").replace("?", "'engineer'"),
                            (int(raw),)).fetchone() if raw.isdigit() else None
    if not engineer:
        return 422, {"error": "Талбаруудыг шалгана уу.",
                     "fields": {"assignee_id": "Инженер эрхтэй ажилтныг сонгоно уу (Тохиргоо → Эрх олгох)."}}
    if engineer["id"] == row["assignee_id"]:
        return 200, {"id": row["id"], "message": "Өөрчлөлт алга."}
    new_status = "assigned" if current == "new" else current
    ts = now_utc().isoformat()
    conn.execute("UPDATE vulnerabilities SET assignee_id = ?, status = ?, updated_at = ?, updated_by = ? WHERE id = ?",
                 (engineer["id"], new_status, ts, user["id"], row["id"]))
    name = _vuln_user_label(engineer)
    _vuln_log(conn, row["id"], user, "updated", "assignee_id", row["assignee_name"] or "", name, note)
    if new_status != current:
        _vuln_log(conn, row["id"], user, "status_changed", "status", current, new_status)
    record_audit(conn, user["id"], "update", "vulnerability", entity_id=row["id"], department_id=row["department_id"],
                 details=f"{_vuln_ref(row)} хариуцагч томилов: {name}")
    conn.commit()
    lines = [f"{_vuln_user_label(user)} таныг дараах эмзэг байдлыг засварлах хариуцагчаар томиллоо.", "",
             f"{_vuln_ref(row)} — {row['title']}",
             f"Түвшин: {VULN_SEV_LABELS.get((row['severity'] or '').lower(), row['severity'])}",
             f"Мэдээллийн хөрөнгө / Систем: {row['asset_name'] or '—'}",
             f"Засварлах хугацаа: {row['due_date'] or '—'}"]
    if note:
        lines += ["", "Тайлбар:", note]
    _vuln_notify([engineer], f"[Эмзэг байдал] {_vuln_ref(row)} танд оноогдлоо", lines, row["id"])
    return 200, {"id": row["id"], "message": f"{name} хариуцагчаар томилогдож, мэдэгдэл илгээлээ."}


def vuln_api_comment(conn, user, row, form):
    """Review comment (append-only, in the activity log). Anyone who can see the record may comment."""
    text = (form.get("comment") or "").strip()
    if not text:
        return 422, {"error": "Сэтгэгдэл бичнэ үү.", "fields": {"comment": "Сэтгэгдэл бичнэ үү."}}
    if len(text) > 5000:
        return 422, {"error": "Хэт урт байна.", "fields": {"comment": "Хамгийн ихдээ 5000 тэмдэгт."}}
    _vuln_log(conn, row["id"], user, "commented", "", "", "", text)
    conn.execute("UPDATE vulnerabilities SET updated_at = ? WHERE id = ?", (now_utc().isoformat(), row["id"]))
    conn.commit()
    return 200, {"id": row["id"], "message": "Сэтгэгдэл нэмэгдлээ."}


def vuln_api_delete(conn, user, row, form):
    """Soft delete (row and its history stay in the database for recovery and audit)."""
    if not vuln_can_delete(user):
        return 403, {"error": "Эрх хүрэлцэхгүй байна."}
    reason = (form.get("reason") or "").strip()[:2000]
    ts = now_utc().isoformat()
    conn.execute("UPDATE vulnerabilities SET deleted_at = ?, deleted_by = ?, updated_at = ?, updated_by = ? WHERE id = ?",
                 (ts, user["id"], ts, user["id"], row["id"]))
    _vuln_log(conn, row["id"], user, "deleted", "", "", "", reason)
    record_audit(conn, user["id"], "delete", "vulnerability", entity_id=row["id"], department_id=row["department_id"],
                 details=f"{_vuln_ref(row)} — {row['title']} устгав (сэргээх боломжтой).{(' Шалтгаан: ' + reason) if reason else ''}")
    conn.commit()
    return 200, {"id": row["id"], "message": "Бүртгэл устгагдлаа."}


def _vuln_fs_items(form):
    if "files" not in form:
        return []
    items = form["files"]
    if not isinstance(items, list):
        items = [items]
    return [it for it in items if getattr(it, "filename", "")]


def vuln_api_upload(conn, user, row, form):
    if not _vuln_can_upload(user, row):
        return 403, {"error": "Эрх хүрэлцэхгүй байна."}
    items = _vuln_fs_items(form)
    if not items:
        return 422, {"error": "Файл сонгоно уу."}
    if len(items) > VULN_FILE_MAX_PER_UPLOAD:
        return 422, {"error": f"Нэг удаад {VULN_FILE_MAX_PER_UPLOAD}-аас ихгүй файл."}
    category = (form.getfirst("category", "") or "").strip() if hasattr(form, "getfirst") else ""
    if category not in VULN_FILE_CATEGORIES:
        return 422, {"error": "Файлын ангилал буруу."}
    for it in items:
        name = Path(str(it.filename).replace("\\", "/")).name
        if Path(name).suffix.lower() not in VULN_FILE_SUFFIXES:
            return 422, {"error": f"«{name}» — зөвшөөрөгдөөгүй файлын төрөл."}
        if category == "as_evidence" and Path(name).suffix.lower() not in VULN_EVIDENCE_SUFFIXES:
            return 422, {"error": f"«{name}» — нотолгоонд зураг, Excel, Word, PDF, TXT файл хавсаргана."}
        if _upload_too_large(it, VULN_FILE_MAX_BYTES):
            return 422, {"error": f"«{name}» — 20 МБ-аас их байна."}
    VULN_FILES_DIR.mkdir(parents=True, exist_ok=True)
    ts = now_utc().isoformat()
    saved = []
    for it in items:
        name = Path(str(it.filename).replace("\\", "/")).name[:255]
        stored = uuid.uuid4().hex + Path(name).suffix.lower()
        data = it.file.read()
        (VULN_FILES_DIR / stored).write_bytes(data)
        conn.execute(
            "INSERT INTO vulnerability_files(vulnerability_id, original_name, stored_name, size, uploaded_by, uploaded_at, category) VALUES (?,?,?,?,?,?,?)",
            (row["id"], name, stored, len(data), user["id"], ts, category))
        _vuln_log(conn, row["id"], user, "file_added", "file", "", name)
        saved.append(name)
    conn.execute("UPDATE vulnerabilities SET updated_at = ?, updated_by = ? WHERE id = ?", (ts, user["id"], row["id"]))
    record_audit(conn, user["id"], "upload", "vulnerability", entity_id=row["id"], department_id=row["department_id"],
                 details=f"{_vuln_ref(row)} нотлох баримт нэмэв: {', '.join(saved)}")
    conn.commit()
    return 200, {"message": f"{len(saved)} файл хавсаргалаа."}


def vuln_file_row(conn, row, file_id):
    return conn.execute("SELECT * FROM vulnerability_files WHERE id = ? AND vulnerability_id = ? AND deleted_at = ''",
                        (file_id, row["id"])).fetchone()


def vuln_api_file_delete(conn, user, row, file_row):
    if not _vuln_can_delete_file(user, row, file_row):
        return 403, {"error": "Эрх хүрэлцэхгүй байна."}
    ts = now_utc().isoformat()
    # Soft delete: the stored file is kept on disk so it can be recovered.
    conn.execute("UPDATE vulnerability_files SET deleted_at = ?, deleted_by = ? WHERE id = ?", (ts, user["id"], file_row["id"]))
    _vuln_log(conn, row["id"], user, "file_deleted", "file", file_row["original_name"], "")
    record_audit(conn, user["id"], "delete", "vulnerability", entity_id=row["id"], department_id=row["department_id"],
                 details=f"{_vuln_ref(row)} нотлох баримт устгав: {file_row['original_name']}")
    conn.commit()
    return 200, {"message": "Файл устгагдлаа."}


_VULN_DEADLINE_LABELS = {"overdue": "Хугацаа хэтэрсэн", "soon": "Хугацаа дөхсөн", "ontrack": "Хугацаандаа",
                         "none": "Хугацаагүй", "done": "Шийдвэрлэсэн"}


def vuln_export(conn, user, query, fmt):
    today = now_utc().date()
    soon_days = vuln_soon_days(conn)
    scope_sql, scope_args = _vuln_scope(user)
    where, args = _vuln_filters(query, user, today, soon_days)
    rows = conn.execute(
        f"{_VULN_SELECT_SQL} WHERE {' AND '.join([scope_sql] + where)} ORDER BY {_vuln_order_sql(query)} LIMIT 100000",
        scope_args + args).fetchall()
    header = ["ID", "Эмзэг байдлын нэр", "CVE", "CVSS", "Түвшин", "Төлөв", "Мэдээллийн хөрөнгө / Систем", "Хөрөнгийн ID", "Хэлтэс",
              "Хөрөнгө эзэмшигч / Хариуцагч", "Ашиглагдаж байгаа эсэх",
              "Манай орчинд энэ эмзэг байдал байгаа эсэх", "Халдлагад өртсөн шинж тэмдэг байгаа эсэх", "Хариуцагч", "Бүртгэсэн огноо", "Засварлах хугацаа", "Хугацааны төлөв", "Хоног",
              "Илрүүлсэн эх сурвалж", "Бүртгэсэн", "Зассан огноо"]
    matrix = [header]
    for r in rows:
        dl = _vuln_deadline(r["status"], r["due_date"], today, soon_days)
        matrix.append([
            _vuln_ref(r), r["title"], r["cve_id"], "" if r["cvss_score"] is None else f"{r['cvss_score']:.1f}",
            VULN_SEV_LABELS.get((r["severity"] or "").lower(), r["severity"]),
            VULN_STATUS_LABELS.get(r["status"], r["status"]), r["asset_name"] or "",
            str(r["asset_id"] or ""), r["department_name"] or "", r["owner_custodian"] or "",
            VULN_IN_USE_LABELS.get(r["in_use"] or "", r["in_use"] or ""),
            VULN_ENV_PRESENT_LABELS.get(r["env_present"] or "", r["env_present"] or ""),
            VULN_COMPROMISE_LABELS.get(r["compromise_signs"] or "", r["compromise_signs"] or ""), r["assignee_name"] or "",
            (r["created_at"] or "")[:10], r["due_date"], _VULN_DEADLINE_LABELS[dl["kind"]],
            "" if dl["days"] is None else str(dl["days"]), r["source"], r["created_by_name"] or "", r["remediated_date"],
        ])
    stamp = today.isoformat()
    record_audit(conn, user["id"], "export", "vulnerability", department_id=user["department_id"],
                 details=f"Эмзэг байдлын жагсаалт экспортлов ({fmt.upper()}, {len(rows)} мөр).")
    conn.commit()
    if fmt == "xlsx":
        return build_xlsx_payload("Эмзэг байдал", matrix), \
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", f"vulnerabilities_{stamp}.xlsx"
    buf = io.StringIO()
    writer = csv.writer(buf)
    for line in matrix:
        # Neutralise spreadsheet formula injection in user-supplied text.
        writer.writerow([("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in line])
    return ("﻿" + buf.getvalue()).encode("utf-8"), "text/csv; charset=utf-8", f"vulnerabilities_{stamp}.csv"


def vuln_json(start_response, status_code, payload):
    status = {200: "200 OK", 403: "403 Forbidden", 404: "404 Not Found", 409: "409 Conflict",
              422: "422 Unprocessable Entity", 400: "400 Bad Request"}.get(status_code, f"{status_code} Error")
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    start_response(status, [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(body))),
                            ("Cache-Control", "no-store")])
    return [body]


# ── VulnReg form designer: InfoSec-managed structure of the registration / engineer / risk forms ─────────
# Schema = app_settings[vuln_forms] (JSON). Each form → ordered sections (cards) → ordered fields.
# Built-in fields map to vulnerabilities columns and drive the workflow: they can be renamed, re-hinted, moved and
# (unless core) hidden or made optional, but never deleted or retyped. Custom fields (key cf_*) are fully managed by
# InfoSec; their values live in vulnerabilities.vuln_custom (JSON {key: value}) and survive field deletion.
VULN_FORMS_SETTING = "vuln_forms"
VULN_FORM_KEYS = ("register", "engineer", "risk")
VULN_FORM_TITLES = {"register": "Эмзэг байдал бүртгэх (InfoSec)", "engineer": "Хөрөнгө ба хариуцлага, үнэлгээ (Инженер)",
                    "risk": "Эрсдэлийн үнэлгээ (InfoSec)"}
VULN_CUSTOM_TYPES = {"text": "Текст", "textarea": "Урт текст", "number": "Тоо", "date": "Огноо",
                     "select": "Сонголт (жагсаалт)", "yesno": "Тийм / Үгүй", "url": "Холбоос (URL)", "email": "И-мэйл"}
_VULN_CF_KEY_RE = re.compile(r"^cf_[a-z0-9]{4,24}$")
_VULN_SEC_ID_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_VULN_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VULN_FORM_MAX_SECTIONS = 20
VULN_FORM_MAX_FIELDS = 120
VULN_FORM_MAX_OPTIONS = 50


def _vb(key, label, typ, core=False, lock_req=False, req=False, full=True, block=False, hint="", ph=""):
    """Built-in field definition. core: cannot be hidden; lock_req: always required; block: rendered by the system."""
    return {"key": key, "label": label, "type": typ, "core": core, "lockReq": lock_req, "required": req or lock_req,
            "full": full, "block": block, "hint": hint, "ph": ph}


VULN_FORM_BUILTINS = {
    "register": [
        ("general", "Ерөнхий мэдээлэл", "", [
            _vb("title", "Эмзэг байдлын нэр", "text", core=True, lock_req=True),
            _vb("cve_id", "CVE", "text", full=False, ph="CVE-2026-12345", hint="Байхгүй бол хоосон үлдээнэ."),
            _vb("source", "Илрүүлсэн эх сурвалж", "text", full=False, ph="NVD, дотоод скан, нэвтрэлтийн тест…"),
            _vb("source_url", "Эх сурвалжийн холбоос", "url", ph="https://"),
            _vb("published_date", "Нийтэлсэн огноо", "date", full=False),
            _vb("reported_date", "Мэдээлсэн огноо", "date", full=False),
            _vb("description", "Тайлбар", "textarea"),
        ]),
        ("risk", "Эрсдэлийн үнэлгээ", "", [
            _vb("cvss_score", "CVSS оноо", "cvss", core=True, lock_req=True, block=True),
            _vb("due_date", "Засварлах хугацаа", "date", full=False, hint="CVSS онооноос автоматаар тооцоолно; гараар өөрчилж болно."),
            _vb("impact", "Нөлөөлөл", "textarea", ph="Ашиглагдвал бизнес, систем, мэдээлэлд үзүүлэх нөлөө"),
            _vb("risk_justification", "Эрсдэлийн үндэслэл", "textarea"),
            _vb("threat_trend", "Аюулын чиг хандлага", "textarea", ph="Идэвхтэй ашиглагдаж байгаа эсэх, exploit нийтлэгдсэн эсэх"),
        ]),
        ("remed", "Засварлах зөвлөмж", "", [
            _vb("scope", "Хамрах хүрээ", "textarea", ph="Нөлөөлөх систем, хувилбар"),
            _vb("verification_method", "Нөлөөллийг шалгах арга", "textarea"),
            _vb("recommendation", "Засварлах зөвлөмж (Patch / Mitigation)", "textarea"),
        ]),
    ],
    "engineer": [
        ("asset_resp", "2. Хөрөнгө ба хариуцлага", "", [
            _vb("affected_asset", "Нөлөөлж болзошгүй хөрөнгө / Систем", "text", core=True, lock_req=True, ph="Хөрөнгө эсвэл системийн нэр"),
            _vb("owner_custodian", "Хөрөнгө эзэмшигч / Хариуцагч", "text", req=True, full=False),
            _vb("in_use", "Ашиглагдаж байгаа эсэх", "select", full=False),
            _vb("env_present", "Манай орчинд энэ эмзэг байдал байгаа эсэх", "select", full=False),
            _vb("compromise_signs", "Халдлагад өртсөн шинж тэмдэг байгаа эсэх", "select", full=False),
        ]),
        ("assess", "Үнэлгээ", "Хөрөнгөд нөлөөлсөн эсэхийг InfoSec тодорхойлно.", [
            _vb("as_scope", "Хамрах хүрээ", "textarea", req=True),
            _vb("as_version", "Одоогийн хувилбар", "text", req=True, full=False),
            _vb("as_internet_facing", "Интернэтэд нээлттэй эсэх", "select", req=True, full=False),
            _vb("as_patch_available", "Patch гарсан эсэх", "select", req=True, full=False),
            _vb("as_test_method", "Шалгасан арга", "textarea", req=True, ph="Скан, хувилбар шалгах, PoC…"),
            _vb("evidence_files", "Нотолгоо (халдлагын баталгаа)", "files", req=True, block=True,
                hint="Зураг, Excel, Word, PDF, TXT · олон файл сонгож болно · нэг файл 20 МБ хүртэл"),
            _vb("as_exploited", "Ашиглагдсан шинж тэмдэг илэрсэн үү? (сэжигтэй лог, хандалт)", "select", core=True, lock_req=True),
            _vb("as_incident_ref", "Зөрчлийн бүртгэлийн дугаар", "text", core=True,
                hint="Тийм бол InfoSec, хүлээн авагчид яаралтай мэдэгдэл очих бөгөөд Зөрчлийн удирдлагын процессыг тусад нь эхлүүлнэ (/incidents/)."),
            _vb("as_conclusion", "Үнэлгээний дүгнэлт", "textarea", core=True, lock_req=True),
        ]),
    ],
    "risk": [
        ("ra", "Эрсдэлийн үнэлгээ", "", [
            _vb("ra_threat", "Аюул (Threat)", "textarea", req=True),
            _vb("impacts", "Нөлөөлөл — 8 шалгуур (1–5)", "impacts", core=True, lock_req=True, block=True),
            _vb("ra_likelihood", "Магадлал (1–5)", "likelihood", core=True, lock_req=True, block=True),
            _vb("ra_decision", "Эрсдэлийн шийдвэр", "decision", core=True, lock_req=True, block=True),
            _vb("ra_decision_note", "Шийдвэрийн үндэслэл", "textarea", core=True,
                hint="Шилжүүлэх, зайлсхийх, хүлээн зөвшөөрөх шийдвэрт заавал бичнэ."),
            _vb("risk_accept_until", "Эрсдэл хүлээн зөвшөөрөх хугацаа (хүртэл)", "date", core=True, lock_req=True, block=True),
        ]),
    ],
}
_VULN_BUILTIN_TYPE_LABELS = {"text": "Текст", "textarea": "Урт текст", "url": "Холбоос (URL)", "date": "Огноо",
                             "select": "Сонголт", "cvss": "CVSS + түвшин + SLA", "files": "Файл хавсралт",
                             "impacts": "8 шалгуурын үнэлгээ", "likelihood": "Магадлал + эрсдэлийн түвшин",
                             "decision": "Шийдвэрийн сонголт"}


def _vuln_builtin_index(form_key):
    return {f["key"]: f for _, _, _, fields in VULN_FORM_BUILTINS[form_key] for f in fields}


def _vuln_form_default(form_key):
    return {"sections": [{"id": sid, "title": title, "desc": desc,
                          "fields": [{"key": f["key"], "label": f["label"], "required": f["required"], "hidden": False,
                                      "hint": f["hint"], "ph": f["ph"], "full": f["full"]} for f in fields]}
                         for sid, title, desc, fields in VULN_FORM_BUILTINS[form_key]]}


def _vuln_clean_text(v, limit):
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(v if v is not None else "")).strip()[:limit]


def _vuln_form_parse(form_key, data, taken_custom_keys=()):
    """Validate one form's schema posted by the designer. Returns (normalized schema, error message or "")."""
    if not isinstance(data, dict) or not isinstance(data.get("sections"), list):
        return None, "Маягтын бүтэц буруу байна."
    builtins = _vuln_builtin_index(form_key)
    secs, seen, sec_ids, total = [], set(), set(), 0
    if not data["sections"]:
        return None, "Дор хаяж нэг хэсэг байх ёстой."
    if len(data["sections"]) > VULN_FORM_MAX_SECTIONS:
        return None, f"Хамгийн ихдээ {VULN_FORM_MAX_SECTIONS} хэсэг."
    for s in data["sections"]:
        if not isinstance(s, dict):
            return None, "Хэсгийн бүтэц буруу."
        sid = str(s.get("id") or "")
        if not _VULN_SEC_ID_RE.match(sid) or sid in sec_ids:
            return None, "Хэсгийн дугаар (id) буруу эсвэл давхардсан."
        sec_ids.add(sid)
        title = _vuln_clean_text(s.get("title"), 120)
        if not title:
            return None, "Хэсэг бүр гарчигтай байна."
        fields = []
        for f in s.get("fields") or []:
            if not isinstance(f, dict):
                return None, "Талбарын бүтэц буруу."
            key = str(f.get("key") or "")
            if key in seen:
                return None, f"Талбар давхардсан: {key}"
            seen.add(key)
            label = _vuln_clean_text(f.get("label"), 200)
            if not label:
                return None, "Талбар бүр нэртэй байна."
            out = {"key": key, "label": label, "required": bool(f.get("required")), "hidden": bool(f.get("hidden")),
                   "hint": _vuln_clean_text(f.get("hint"), 300), "ph": _vuln_clean_text(f.get("ph"), 200),
                   "full": bool(f.get("full"))}
            if key in builtins:
                b = builtins[key]
                if b["core"]:
                    out["hidden"] = False
                if b["lockReq"]:
                    out["required"] = True
                if b["block"]:
                    out["full"], out["ph"] = True, ""
                if out["hidden"]:
                    out["required"] = False
            elif _VULN_CF_KEY_RE.match(key):
                if key in taken_custom_keys:
                    return None, f"«{label}» талбарын түлхүүр өөр маягтад ашиглагдсан байна."
                typ = str(f.get("type") or "")
                if typ not in VULN_CUSTOM_TYPES:
                    return None, f"«{label}» талбарын төрөл буруу."
                out["type"] = typ
                if typ == "select":
                    opts, oseen = [], set()
                    for o in f.get("options") or []:
                        o = _vuln_clean_text(o, 120)
                        if o and o not in oseen:
                            oseen.add(o)
                            opts.append(o)
                    if not opts:
                        return None, f"«{label}» жагсаалтад дор хаяж нэг сонголт оруулна уу."
                    if len(opts) > VULN_FORM_MAX_OPTIONS:
                        return None, f"«{label}»: хамгийн ихдээ {VULN_FORM_MAX_OPTIONS} сонголт."
                    out["options"] = opts
                if typ in ("text", "textarea"):
                    try:
                        mx = int(f.get("max") or 0)
                    except (TypeError, ValueError):
                        mx = 0
                    cap = 10000 if typ == "textarea" else 1000
                    out["max"] = mx if 1 <= mx <= cap else (5000 if typ == "textarea" else 300)
                if typ in ("select", "yesno", "date"):
                    out["ph"] = ""
                if out["hidden"]:
                    out["required"] = False
            else:
                return None, f"Үл мэдэгдэх талбар: {key}"
            fields.append(out)
            total += 1
        secs.append({"id": sid, "title": title, "desc": _vuln_clean_text(s.get("desc"), 500), "fields": fields})
    if total > VULN_FORM_MAX_FIELDS:
        return None, f"Хамгийн ихдээ {VULN_FORM_MAX_FIELDS} талбар."
    missing = [builtins[k]["label"] for k in builtins if k not in seen]
    if missing:
        return None, "Системийн талбарыг устгах боломжгүй (нууж болно): " + ", ".join(missing)
    return {"sections": secs}, ""


def _vuln_forms_raw(conn):
    try:
        data = json.loads(get_setting(conn, VULN_FORMS_SETTING, "") or "{}")
    except (TypeError, ValueError):
        data = {}
    return data if isinstance(data, dict) else {}


def _vuln_form_stored(conn, form_key, raw=None):
    """The saved schema of one form, repaired against the built-in registry (falls back to the default)."""
    raw = _vuln_forms_raw(conn) if raw is None else raw
    data = raw.get(form_key)
    if not isinstance(data, dict):
        return _vuln_form_default(form_key)
    # Built-ins added by later versions (or lost) go back to their default section, else the first one.
    builtins = _vuln_builtin_index(form_key)
    present = {f.get("key") for s in data.get("sections") or [] if isinstance(s, dict) for f in s.get("fields") or [] if isinstance(f, dict)}
    data = json.loads(json.dumps(data))
    secs = [s for s in data.get("sections") or [] if isinstance(s, dict)]
    if secs:
        for sid, _t, _d, fields in VULN_FORM_BUILTINS[form_key]:
            for b in fields:
                if b["key"] in present:
                    continue
                target = next((s for s in secs if s.get("id") == sid), secs[0])
                target.setdefault("fields", []).append({"key": b["key"], "label": b["label"], "required": b["required"],
                                                        "hidden": False, "hint": b["hint"], "ph": b["ph"], "full": b["full"]})
    data["sections"] = secs
    parsed, err = _vuln_form_parse(form_key, data)
    return parsed if parsed and not err else _vuln_form_default(form_key)


def vuln_form_schema(conn, form_key, raw=None):
    """One form for rendering: stored schema with the built-in flags (core / lockReq / block / type) attached."""
    builtins = _vuln_builtin_index(form_key)
    form = _vuln_form_stored(conn, form_key, raw)
    for s in form["sections"]:
        for f in s["fields"]:
            b = builtins.get(f["key"])
            f["builtin"] = bool(b)
            if b:
                f.update(type=b["type"], core=b["core"], lockReq=b["lockReq"], block=b["block"],
                         typeLabel=_VULN_BUILTIN_TYPE_LABELS.get(b["type"], b["type"]))
            else:
                f.update(core=False, lockReq=False, block=False, typeLabel=VULN_CUSTOM_TYPES[f["type"]])
    form["title"] = VULN_FORM_TITLES[form_key]
    return form


def vuln_forms_all(conn):
    raw = _vuln_forms_raw(conn)
    return {k: vuln_form_schema(conn, k, raw) for k in VULN_FORM_KEYS}


def _vuln_form_fields(form):
    return [f for s in form["sections"] for f in s["fields"]]


def vuln_form_field(form, key):
    return next((f for f in _vuln_form_fields(form) if f["key"] == key), None)


def vuln_form_visible(form, key):
    f = vuln_form_field(form, key)
    return bool(f) and not f["hidden"]


def vuln_form_required(form, key):
    f = vuln_form_field(form, key)
    return bool(f) and not f["hidden"] and f["required"]


def vuln_custom_values(row):
    try:
        data = json.loads((row["vuln_custom"] if row is not None else "") or "{}")
    except (TypeError, ValueError, KeyError, IndexError):
        data = {}
    return data if isinstance(data, dict) else {}


def vuln_custom_labels(conn):
    """{cf_key: label} across all forms (for the activity log)."""
    return {f["key"]: f["label"] for form in vuln_forms_all(conn).values() for f in _vuln_form_fields(form) if not f["builtin"]}


def _vuln_custom_parse(conn, form_key, form, row, enforce_required):
    """Custom field values posted for one form. Fields not posted keep their stored value.

    Returns (merged {key: value} for the record, errors)."""
    schema = vuln_form_schema(conn, form_key)
    merged = vuln_custom_values(row)
    errors = {}
    for f in _vuln_form_fields(schema):
        if f["builtin"]:
            continue
        key, typ = f["key"], f["type"]
        if key not in form:
            v = str(merged.get(key, "") or "")
        else:
            v = (form.get(key) or "").strip()
            if typ in ("text", "textarea") and len(v) > f.get("max", 5000):
                errors[key] = f"Хамгийн ихдээ {f.get('max', 5000)} тэмдэгт."
            elif v and typ == "number":
                try:
                    num = Decimal(v.replace(",", "."))
                    if not num.is_finite() or len(v) > 40:
                        raise ValueError
                    v = format(num.normalize(), "f")
                except (ArithmeticError, ValueError):
                    errors[key] = "Тоо оруулна уу."
            elif v and typ == "date" and not _valid_iso_date(v):
                errors[key] = "Огноо буруу форматтай байна."
            elif v and typ == "select" and v not in f.get("options", []):
                errors[key] = "Жагсаалтаас сонгоно уу."
            elif v and typ == "yesno" and v not in ("yes", "no"):
                errors[key] = "Тийм эсвэл Үгүй сонгоно уу."
            elif v and typ == "url":
                p = urlparse(v)
                if p.scheme not in ("http", "https") or not p.netloc or len(v) > 2000:
                    errors[key] = "http:// эсвэл https://-ээр эхэлсэн холбоос оруулна уу."
            elif v and typ == "email" and (not _VULN_EMAIL_RE.match(v) or len(v) > 254):
                errors[key] = "И-мэйл хаяг буруу байна."
        if enforce_required and f["required"] and not f["hidden"] and not v and key not in errors:
            errors[key] = "Заавал бөглөнө."
        if key not in errors:
            if v:
                merged[key] = v
            else:
                merged.pop(key, None)
    return merged, errors


def _vuln_custom_display(conn, key, value):
    if value in (None, ""):
        return ""
    for form in vuln_forms_all(conn).values():
        f = vuln_form_field(form, key)
        if f and not f["builtin"] and f["type"] == "yesno":
            return {"yes": "Тийм", "no": "Үгүй"}.get(value, value)
    return value


def _vuln_custom_log(conn, row, user, old, new):
    """Activity log: one entry per changed custom field (field = cf_* key; label resolved when shown)."""
    for key in sorted(set(old) | set(new)):
        if str(old.get(key, "")) != str(new.get(key, "")):
            _vuln_log(conn, row["id"], user, "updated", key, _vuln_custom_display(conn, key, old.get(key, "")),
                      _vuln_custom_display(conn, key, new.get(key, "")))


def _vuln_form_summary(form):
    parts = []
    for s in form["sections"]:
        names = []
        for f in s["fields"]:
            t = f["label"] + ("*" if f["required"] else "")
            if f["hidden"]:
                t += " (нуусан)"
            if f["key"].startswith("cf_"):
                t += f" [{VULN_CUSTOM_TYPES.get(f.get('type'), '')}" + (": " + " / ".join(f.get("options", [])) if f.get("options") else "") + "]"
            names.append(t)
        parts.append(f"{s['title']}: " + ", ".join(names) if names else f"{s['title']}: —")
    return " | ".join(parts)


def vuln_forms_save(conn, user, form, reason):
    form_key = form.get("form_key", "")
    if form_key not in VULN_FORM_KEYS:
        return 422, {"error": "Маягт буруу байна."}
    try:
        data = json.loads(form.get("schema") or "")
    except (TypeError, ValueError):
        return 422, {"error": "Маягтын бүтэц буруу байна."}
    raw = _vuln_forms_raw(conn)
    taken = {f["key"] for k in VULN_FORM_KEYS if k != form_key
             for f in _vuln_form_fields(_vuln_form_stored(conn, k, raw)) if f["key"].startswith("cf_")}
    new, err = _vuln_form_parse(form_key, data, taken)
    if err:
        return 422, {"error": err}
    old = _vuln_form_stored(conn, form_key, raw)
    if old == new:
        return 200, {"message": "Өөрчлөлт алга."}
    raw[form_key] = new
    set_setting(conn, VULN_FORMS_SETTING, json.dumps(raw, ensure_ascii=False))
    _vuln_config_log(conn, user, f"{VULN_FORMS_SETTING}:{form_key}", f"Маягтын бүтэц — {VULN_FORM_TITLES[form_key]}",
                     _vuln_form_summary(old), _vuln_form_summary(new), reason)
    conn.commit()
    return 200, {"message": f"«{VULN_FORM_TITLES[form_key]}» маягтын бүтэц хадгалагдлаа."}


# ── VulnReg settings (Phase 1: SLA policy, deadline warning, change history) ──────────────
VULN_SETTINGS_TEMPLATE = BASE_DIR / "templates" / "vuln_settings.html"
_VULN_SETTING_ENTITY = "vuln_setting"
_VULN_SLA_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def vuln_is_infosec_strict(user):
    """True only for users holding the InfoSec VulnReg role — Superadmin gets no implicit pass here."""
    return "infosec" in _vroles(user)


def vuln_can_view_settings(user):
    """Settings menu/page/API: Information Security (InfoSec) personnel only — enforced on every settings route."""
    return vuln_is_infosec_strict(user)


def vuln_can_edit_settings(user):
    return vuln_is_infosec_strict(user)


def _vuln_sla_text(sla):
    return "; ".join(
        f"{_VULN_SLA_LABELS[l]} ≥{sla[l]['min']:.1f} → {sla[l]['days']} хоног" if l != "low"
        else f"Low >0 → {sla[l]['days']} хоног" for l in VULN_SLA_LEVELS)


VULN_REASON_MAX = 2000


def _vuln_reason(form):
    """Optional change reason (the Settings UI no longer asks for one). Returns (reason, error-dict)."""
    reason = (form.get("reason") or "").strip()
    if len(reason) > VULN_REASON_MAX:
        return "", {"reason": f"Хамгийн ихдээ {VULN_REASON_MAX} тэмдэгт."}
    return reason, {}


def _vuln_config_log(conn, user, setting, label, old, new, reason):
    """Append to the configuration audit log (who, when, previous value, new value, reason) + the global audit log."""
    conn.execute(
        """INSERT INTO vuln_config_audit(actor_user_id, actor_name, setting, label, old_value, new_value, reason, created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (user["id"], _vuln_user_label(user), setting, label, "" if old is None else str(old), "" if new is None else str(new),
         reason, now_utc().isoformat()))
    record_audit(conn, user["id"], "update", _VULN_SETTING_ENTITY, entity_id=setting,
                 details=f"{label}: {old or '—'} ⇒ {new or '—'}." + (f" Шалтгаан: {reason}" if reason else ""))


def _vuln_settings_history(conn, limit=100):
    rows = conn.execute("SELECT * FROM vuln_config_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = [{"at": r["created_at"], "actor": r["actor_name"] or "—", "setting": r["label"] or r["setting"],
            "old": r["old_value"], "new": r["new_value"], "reason": r["reason"]} for r in rows]
    if len(out) < limit:
        # Changes made before reasons were recorded (kept in the global audit log).
        legacy = conn.execute(
            """SELECT l.created_at, l.details, COALESCE(NULLIF(l.actor_name, ''), u.display_name, u.email, '') AS actor
               FROM audit_logs l LEFT JOIN users u ON u.id = l.actor_user_id
               WHERE l.entity_type = ? AND l.details NOT LIKE '%Шалтгаан:%' ORDER BY l.id DESC LIMIT ?""",
            (_VULN_SETTING_ENTITY, limit - len(out))).fetchall()
        out += [{"at": r["created_at"], "actor": r["actor"] or "—", "setting": "", "old": "", "new": r["details"], "reason": ""}
                for r in legacy]
    return out


def _vuln_settings_users(conn):
    return [{"id": r["id"], "name": _vuln_user_label(r), "email": r["email"] or "", "dept": r["dept"] or "",
             "roles": vuln_roles_of(r), "superadmin": r["role"] == ROLE_SUPERADMIN}
            for r in conn.execute(
                """SELECT u.id, u.display_name, u.username, u.email, u.role, u.vuln_role, d.name AS dept FROM users u
                   LEFT JOIN departments d ON d.id = u.department_id WHERE u.is_active = 1
                   ORDER BY COALESCE(NULLIF(u.display_name, ''), u.username)""")]


def _vuln_substitutes(conn):
    today = _vuln_today()
    rows = conn.execute(
        f"""SELECT s.*, {_uname_sql('p')} AS principal_name, {_uname_sql('q')} AS substitute_name, {_uname_sql('c')} AS created_name
            FROM vuln_substitutes s LEFT JOIN users p ON p.id = s.principal_id LEFT JOIN users q ON q.id = s.substitute_id
            LEFT JOIN users c ON c.id = s.created_by
            WHERE s.revoked_at = '' AND s.end_date >= ? ORDER BY s.start_date, s.id""", (today,)).fetchall()
    return [{"id": r["id"], "role": r["role"], "roleLabel": VULN_ROLE_LABELS.get(r["role"], r["role"]),
             "principal": r["principal_name"] or "", "principalId": r["principal_id"], "substitute": r["substitute_name"] or "",
             "substituteId": r["substitute_id"], "start": r["start_date"], "end": r["end_date"], "note": r["note"],
             "active": r["start_date"] <= today <= r["end_date"], "createdBy": r["created_name"] or ""} for r in rows]


def vuln_api_settings(conn, user):
    if not vuln_can_view_settings(user):
        return 403, {"error": "Тохиргоо зөвхөн админ эрхтэй (InfoSec) хэрэглэгчид харагдана."}
    return 200, {
        "canEdit": vuln_can_edit_settings(user),
        "sla": vuln_sla(conn), "slaDefault": VULN_SLA_DEFAULT, "slaMaxDays": VULN_SLA_MAX_DAYS,
        "dueSoonDays": vuln_soon_days(conn), "dueSoonDefault": VULN_DUE_SOON_DEFAULT,
        "roles": [{"key": r, "label": VULN_ROLE_LABELS[r]} for r in VULN_ROLES],
        "users": _vuln_settings_users(conn),
        "perms": vuln_role_perms(conn), "permKeys": [{"key": p, "label": VULN_PERM_LABELS[p]} for p in VULN_PERMS],
        "permsLocked": [list(x) for x in sorted(VULN_PERMS_LOCKED)],
        "substitutes": _vuln_substitutes(conn), "substitutableRoles": list(VULN_SUBSTITUTABLE_ROLES),
        "risk": vuln_risk_config(conn), "riskDefault": VULN_RISK_DEFAULT,
        "forms": vuln_forms_all(conn),
        "formsDefault": {k: _vuln_form_default(k) for k in VULN_FORM_KEYS},
        "customTypes": [{"key": k, "label": v} for k, v in VULN_CUSTOM_TYPES.items()],
        "history": _vuln_settings_history(conn),
        "selfId": user["id"],
    }


def _vuln_parse_sla_form(form):
    """Form fields <level>_min / <level>_days -> (sla dict, field errors)."""
    sla, errors = {}, {}
    for level in VULN_SLA_LEVELS:
        band = {}
        days_raw = (form.get(f"{level}_days") or "").strip()
        band["days"] = int(days_raw) if days_raw.isdigit() and len(days_raw) <= 4 else None
        if band["days"] is None:
            errors[f"{level}_days"] = f"1–{VULN_SLA_MAX_DAYS} хоорондох бүхэл тоо оруулна уу."
        if level == "low":
            band["min"] = 0.1
        else:
            min_raw = (form.get(f"{level}_min") or "").strip().replace(",", ".")
            try:
                band["min"] = float(Decimal(min_raw).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))
            except (ArithmeticError, ValueError):
                band["min"] = None
                errors[f"{level}_min"] = "Тоо оруулна уу (жишээ: 7.0)."
        sla[level] = band
    return sla, dict(_vuln_sla_errors(sla), **errors)


def _vuln_role_text(conn, uid):
    return _vuln_user_label(_vuln_user_by_id(conn, uid)) or f"#{uid}"


def vuln_api_settings_save(conn, user, form):
    """Save one settings section. Every change is written to vuln_config_audit (who, when, old → new)."""
    if not vuln_can_edit_settings(user):
        return 403, {"error": "Тохиргоо өөрчлөх эрхгүй байна (зөвхөн админ — InfoSec)."}
    section = form.get("section", "")
    reason, rerr = _vuln_reason(form)

    if section == "sla":
        sla, errors = _vuln_parse_sla_form(form)
        errors.update(rerr)
        if errors:
            return 422, {"error": "Талбаруудыг шалгана уу.", "fields": errors}
        old = vuln_sla(conn)
        if old == sla:
            return 200, {"message": "Өөрчлөлт алга.", "sla": old}
        set_setting(conn, VULN_SLA_SETTING, json.dumps(sla))
        _vuln_config_log(conn, user, VULN_SLA_SETTING, "Засварлах хугацаа (SLA)", _vuln_sla_text(old), _vuln_sla_text(sla), reason)
        conn.commit()
        return 200, {"message": "Засварлах хугацааны тохиргоо хадгалагдлаа. Шинэ бүртгэлд хэрэгжинэ.", "sla": sla}

    if section == "deadline":
        raw = (form.get("due_soon_days") or "").strip()
        errors = dict(rerr)
        if not (raw.isdigit() and 0 <= int(raw) <= 90):
            errors["due_soon_days"] = "0–90 хоорондох бүхэл тоо оруулна уу."
        if errors:
            return 422, {"error": "Талбаруудыг шалгана уу.", "fields": errors}
        old, new = vuln_soon_days(conn), int(raw)
        if old == new:
            return 200, {"message": "Өөрчлөлт алга.", "dueSoonDays": old}
        set_setting(conn, VULN_DUE_SOON_SETTING, str(new))
        _vuln_config_log(conn, user, VULN_DUE_SOON_SETTING, "«Хугацаа дөхсөн» босго", f"{old} хоног", f"{new} хоног", reason)
        conn.commit()
        return 200, {"message": "Хугацааны сануулгын тохиргоо хадгалагдлаа.", "dueSoonDays": new}

    if section == "role":
        return 410, {"error": "Эрхийг Хэрэглэгчид хуудаснаас (Засах) удирдана."}
    if section == "forms":
        # Form Structure: no change reason is asked for; the before/after summary is still written to the audit log.
        return vuln_forms_save(conn, user, form, "")
    if section == "perms":
        if rerr:
            return 422, {"error": "Талбаруудыг шалгана уу.", "fields": rerr}
        old = vuln_role_perms(conn)
        new = json.loads(json.dumps(old))
        for role in VULN_ROLES:
            for perm in VULN_PERMS:
                if (role, perm) in VULN_PERMS_LOCKED:
                    continue
                new[role][perm] = form.get(f"{role}__{perm}") == "1"
        diffs = [(r, p) for r in VULN_ROLES for p in VULN_PERMS if old[r][p] != new[r][p]]
        if not diffs:
            return 200, {"message": "Өөрчлөлт алга.", "perms": old}
        set_setting(conn, VULN_PERMS_SETTING, json.dumps(new))
        yn = lambda b: "Тийм" if b else "Үгүй"
        for r, p in diffs:
            _vuln_config_log(conn, user, f"perm:{r}:{p}", f"Хандах эрх — {VULN_ROLE_LABELS[r]} / {VULN_PERM_LABELS[p]}",
                             yn(old[r][p]), yn(new[r][p]), reason)
        conn.commit()
        return 200, {"message": f"Хандах эрхийн тохиргоо хадгалагдлаа ({len(diffs)} өөрчлөлт).", "perms": new}

    if section == "substitute_add":
        # No separate change reason here: the «Тайлбар» (note) is recorded as the audit reason.
        errors = {}
        role = (form.get("role") or "").strip()
        if role not in VULN_SUBSTITUTABLE_ROLES:
            errors["role"] = "InfoSec, Хүлээн авагч эсвэл CTO-г сонгоно уу."
        def _uid(key):
            raw = (form.get(key) or "").strip()
            return conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (int(raw),)).fetchone() if raw.isdigit() else None
        principal, sub = _uid("principal_id"), _uid("substitute_id")
        if not principal:
            errors["principal_id"] = "Орлуулагдах ажилтныг сонгоно уу."
        elif role in VULN_SUBSTITUTABLE_ROLES and role not in vuln_roles_of(principal):
            errors["principal_id"] = f"Сонгосон ажилтан «{VULN_ROLE_LABELS[role]}» эрхгүй байна."
        if not sub:
            errors["substitute_id"] = "Орлон гүйцэтгэгчийг сонгоно уу."
        elif principal and sub["id"] == principal["id"]:
            errors["substitute_id"] = "Өөр ажилтан сонгоно уу."
        elif sub["id"] == user["id"]:
            # An InfoSec delegate holds Settings rights; stop them extending their own delegation.
            errors["substitute_id"] = "Өөрийгөө орлон гүйцэтгэгчээр томилох боломжгүй."
        start, end = (form.get("start_date") or "").strip(), (form.get("end_date") or "").strip()
        if not _valid_iso_date(start):
            errors["start_date"] = "Эхлэх огноо оруулна уу."
        if not _valid_iso_date(end):
            errors["end_date"] = "Дуусах огноо оруулна уу."
        elif "start_date" not in errors and end < start:
            errors["end_date"] = "Эхлэх огнооноос өмнө байж болохгүй."
        elif end < _vuln_today():
            errors["end_date"] = "Өнгөрсөн хугацаанд орлох томилох боломжгүй."
        if not errors and conn.execute(
                """SELECT 1 FROM vuln_substitutes WHERE role = ? AND principal_id = ? AND substitute_id = ? AND revoked_at = ''
                   AND start_date <= ? AND end_date >= ?""", (role, principal["id"], sub["id"], end, start)).fetchone():
            errors["start_date"] = "Энэ хугацаанд давхардсан орлох томилгоо байна."
        if errors:
            return 422, {"error": "Талбаруудыг шалгана уу.", "fields": errors}
        note = (form.get("note") or "").strip()[:500]
        cur = conn.execute(
            """INSERT INTO vuln_substitutes(role, principal_id, substitute_id, start_date, end_date, note, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?)""", (role, principal["id"], sub["id"], start, end, note, user["id"], now_utc().isoformat()))
        _vuln_config_log(conn, user, f"substitute:{cur.lastrowid}", f"Орлон гүйцэтгэгч — {VULN_ROLE_LABELS[role]}", "",
                         f"{_vuln_user_label(principal)} → {_vuln_user_label(sub)}, {start} – {end}", note)
        conn.commit()
        _vuln_notify([sub], "[Эмзэг байдал] Таныг орлон гүйцэтгэгчээр томиллоо", [
            f"{_vuln_user_label(user)} таныг {start} – {end} хугацаанд {_vuln_user_label(principal)}-ийн "
            f"({VULN_ROLE_LABELS[role]}) оронд эмзэг байдлын бүртгэлийн тухайн үүргийг гүйцэтгэхээр томиллоо.",
        ] + ([f"Тайлбар: {note}"] if note else []), 0)
        return 200, {"message": "Орлон гүйцэтгэгч томилогдлоо."}

    if section == "substitute_revoke":
        sid = (form.get("id") or "").strip()
        r = conn.execute("SELECT * FROM vuln_substitutes WHERE id = ? AND revoked_at = ''", (int(sid),)).fetchone() if sid.isdigit() else None
        if not r:
            return 404, {"error": "Томилгоо олдсонгүй."}
        if rerr:
            return 422, {"error": "Талбаруудыг шалгана уу.", "fields": rerr}
        conn.execute("UPDATE vuln_substitutes SET revoked_at = ?, revoked_by = ? WHERE id = ?", (now_utc().isoformat(), user["id"], r["id"]))
        _vuln_config_log(conn, user, f"substitute:{r['id']}", f"Орлон гүйцэтгэгч цуцлах — {VULN_ROLE_LABELS.get(r['role'], r['role'])}",
                         f"{_vuln_role_text(conn, r['principal_id'])} → {_vuln_role_text(conn, r['substitute_id'])}, "
                         f"{r['start_date']} – {r['end_date']}", "Цуцалсан", reason)
        conn.commit()
        return 200, {"message": "Орлох томилгоог цуцаллаа."}

    if section == "risk":
        errors = dict(rerr)
        crit = [(form.get(f"criterion_{i}") or "").strip()[:120] for i in range(1, 9)]
        for i, c in enumerate(crit, 1):
            if not c:
                errors[f"criterion_{i}"] = "Нэр оруулна уу."
        lo, med = (form.get("low_max") or "").strip(), (form.get("medium_max") or "").strip()
        lo = int(lo) if lo.isdigit() else None
        med = int(med) if med.isdigit() else None
        if lo is None or not 1 <= lo <= 23:
            errors["low_max"] = "1–23 хооронд."
        if med is None or not 2 <= med <= 24:
            errors["medium_max"] = "2–24 хооронд."
        elif lo is not None and med <= lo:
            errors["medium_max"] = "Бага (Low)-ийн дээд хязгаараас их байх ёстой."
        if errors:
            return 422, {"error": "Талбаруудыг шалгана уу.", "fields": errors}
        old = vuln_risk_config(conn)
        new = {"criteria": crit, "low_max": lo, "medium_max": med}
        if old == new:
            return 200, {"message": "Өөрчлөлт алга.", "risk": old}
        set_setting(conn, VULN_RISK_SETTING, json.dumps(new, ensure_ascii=False))
        fmt = lambda c: f"Low ≤{c['low_max']}, Medium ≤{c['medium_max']}, High >{c['medium_max']}; шалгуур: " + ", ".join(c["criteria"])
        _vuln_config_log(conn, user, VULN_RISK_SETTING, "Эрсдэлийн матриц (MAS-14)", fmt(old), fmt(new), reason)
        conn.commit()
        return 200, {"message": "Эрсдэлийн матрицын тохиргоо хадгалагдлаа.", "risk": new}

    return 400, {"error": "Буруу хүсэлт."}


def _vuln_recalc_plan(conn, sla):
    """Open records whose severity / SLA days differ from the current policy, with their new values.

    The due date is moved only when it was derived automatically (reported date, else registration date,
    + the stored SLA days); a manually entered due date is kept.
    """
    rows = conn.execute(
        f"SELECT v.* FROM vulnerabilities v WHERE v.deleted_at = '' AND {_VULN_OPEN_SQL} AND v.cvss_score IS NOT NULL "
        "ORDER BY v.id").fetchall()
    plan = []
    for r in rows:
        sev, days = cvss_severity(r["cvss_score"], sla)
        if sev == (r["severity"] or "") and days == r["remediation_days"]:
            continue
        base_raw = r["reported_date"] or (r["created_at"] or "")[:10]
        try:
            base = dt.date.fromisoformat(base_raw)
        except ValueError:
            base = None
        due = r["due_date"] or ""
        auto = base is not None and (
            not due or (r["remediation_days"] is not None and due == (base + dt.timedelta(days=r["remediation_days"])).isoformat()))
        new_due = due
        if auto and days is not None:
            new_due = (base + dt.timedelta(days=days)).isoformat()
        plan.append({"row": r, "severity": sev, "days": days, "due": new_due, "manual_due": not auto})
    return plan


def vuln_api_settings_recalc(conn, user, form):
    if not vuln_can_edit_settings(user):
        return 403, {"error": "Тохиргоо өөрчлөх эрхгүй байна (зөвхөн админ — InfoSec)."}
    sla = vuln_sla(conn)
    plan = _vuln_recalc_plan(conn, sla)
    summary = {
        "affected": len(plan),
        "dueChanged": sum(1 for p in plan if p["due"] != (p["row"]["due_date"] or "")),
        "manualDueKept": sum(1 for p in plan if p["manual_due"]),
        "sample": [_vuln_ref(p["row"]) for p in plan[:10]],
    }
    if form.get("dry_run") == "1" or not plan:
        return 200, dict(summary, dryRun=True)
    reason, rerr = _vuln_reason(form)
    if rerr:
        return 422, {"error": "Өөрчлөлтийн шалтгааныг бичнэ үү.", "fields": rerr}
    ts = now_utc().isoformat()
    note = "SLA тохиргооны дагуу дахин тооцоолов."
    for p in plan:
        r = p["row"]
        conn.execute("UPDATE vulnerabilities SET severity = ?, remediation_days = ?, due_date = ?, updated_at = ?, updated_by = ? "
                     "WHERE id = ?", (p["severity"], p["days"], p["due"], ts, user["id"], r["id"]))
        if p["severity"] != (r["severity"] or ""):
            _vuln_log(conn, r["id"], user, "updated", "severity", r["severity"], p["severity"], note)
        if p["due"] != (r["due_date"] or ""):
            _vuln_log(conn, r["id"], user, "updated", "due_date", r["due_date"], p["due"], note)
    _vuln_config_log(conn, user, "recalc", "Нээлттэй бүртгэлийг SLA-ийн дагуу дахин тооцоолох",
                     ", ".join(_vuln_ref(p["row"]) for p in plan[:20]) + (" …" if len(plan) > 20 else ""),
                     f"{len(plan)} бүртгэл шинэчлэгдсэн (хугацаа шилжсэн: {summary['dueChanged']}, "
                     f"гараар оруулсан хугацаа хадгалсан: {summary['manualDueKept']})", reason)
    conn.commit()
    return 200, dict(summary, dryRun=False, message=f"{len(plan)} бүртгэл шинэчлэгдлээ.")


def list_vulnerabilities(conn, user):
    """Saved vulnerabilities for the dashboard table (same visibility rules as the Vulnerabilities page)."""
    ensure_vulnerabilities_table(conn)
    scope_sql, scope_args = _vuln_scope(user)
    rows = conn.execute(_VULN_SELECT_SQL + f" WHERE {scope_sql} ORDER BY v.id DESC", scope_args).fetchall()
    out = []
    for r in rows:
        created = (r["created_at"] or "")[:10]
        out.append({
            "id": r["id"],
            "ref": _vuln_ref(r),
            "cve": r["cve_id"], "title": r["title"],
            "source": r["source"], "sourceUrl": r["source_url"],
            "published": r["published_date"], "reported": r["reported_date"],
            "description": r["description"], "threatTrend": r["threat_trend"], "scope": r["scope"],
            "verification": r["verification_method"], "recommendation": r["recommendation"],
            "cvss": r["cvss_score"], "sev": (r["severity"] or "").lower(),
            "days": r["remediation_days"], "due": r["due_date"],
            "status": r["status"] or "new", "statusLabel": VULN_STATUS_LABELS.get(r["status"] or "new", ""),
            "dept": r["department_name"] or "", "createdBy": r["created_by_name"] or "", "created": created,
        })
    return out


VULN_LIST_TEMPLATE = BASE_DIR / "templates" / "vuln_list.html"
VULN_DETAIL_TEMPLATE = BASE_DIR / "templates" / "vuln_detail.html"
_VULNREG_STATIC = {"vulnreg.css": "text/css; charset=utf-8", "vulnreg.js": "application/javascript; charset=utf-8"}


def _vulnreg_sidebar(conn, user, active):
    """VulnReg shell sidebar; the «Эмзэг байдал» badge counts records waiting on this user (see _vuln_todo_sql)."""
    todo = vuln_todo_count(conn, user)
    def item(key, href, icon, label, badge=0, neutral=False):
        cur = ' aria-current="page"' if key == active else ""
        b = f'<span class="sb-badge{" neutral" if neutral else ""}" aria-hidden="true">{badge}</span>' if badge else ""
        tip = f"{label} ({badge})" if badge else label
        return (f'<li><a class="sb-item" href="{html.escape(href)}"{cur} data-tip="{html.escape(tip)}" aria-label="{html.escape(tip)}">'
                f'<svg class="ico" aria-hidden="true"><use href="#i-{icon}"/></svg><span class="sb-text">{html.escape(label)}</span>{b}</a></li>')

    def section(label, items):
        items = [i for i in items if i]
        if not items:
            return ""
        return f'<div class="sb-section"><div class="sb-label">{html.escape(label)}</div><ul class="sb-list">{"".join(items)}</ul></div>'

    return "".join([
        section("Хяналт", [
            item("dashboard", "/registry/vulnerabilities/dashboard", "grid", "Хяналтын самбар") if vuln_perm(user, "dashboard") else "",
        ]),
        section("Бүртгэл", [
            item("vulns", "/registry/vulnerabilities", "bug", "Эмзэг байдал", todo),
        ]),
        section("Тохиргоо", [
            item("settings", "/registry/vulnerabilities/settings", "cog", "Тохиргоо") if vuln_can_view_settings(user) else "",
        ]),
        section("Тусламж", [item("guide", "/guide#vulnreg", "file", "Гарын авлага")]),
    ])


def _vulnreg_page(conn, user, template, active, boot):
    name = (user["display_name"] or user["username"] or user["email"] or "").strip()
    parts = [p for p in re.split(r"[\s.]+", name) if p]
    initials = "".join(p[0] for p in parts[-2:]).upper() or "?"
    role = user_role(user)
    user = vuln_user(conn, user)
    vr = user["_vrole"]
    role_label = vuln_roles_text(vr) if vr else ({ROLE_SUPERADMIN: "Супер админ"}.get(role, "Хэрэглэгч"))
    if user["_vsubs"]:
        role_label += " · орлон: " + ", ".join(VULN_ROLE_LABELS[s["role"]] for s in user["_vsubs"])
    page = template.read_text(encoding="utf-8")
    for key, value in (("{{USER_NAME}}", name or "-"), ("{{USER_INITIALS}}", initials), ("{{USER_ROLE}}", role_label)):
        page = page.replace(key, html.escape(value, quote=True))
    page = page.replace("{{SIDEBAR}}", _vulnreg_sidebar(conn, user, active))
    boot = dict(boot, csrf=_csrf_token(), userId=user["id"], role=role,
                canManage=vuln_can_manage(user), canDelete=vuln_can_delete(user), canExport=vuln_perm(user, "export"),
                isItHead=vuln_can_assign(user) or vuln_is_any_reviewer(user), isCto=vuln_is_cto(user), isAdmin=vuln_is_admin(user),
                vulnRoles=sorted(user["_vroles"]), sla=vuln_sla(conn), todoCount=vuln_todo_count(conn, user),
                forms=vuln_forms_all(conn))
    return page.replace("{{BOOT_JSON}}", _script_json(boot))


def vulnerability_dashboard_page(conn, user, notice="", error=""):
    """VulnReg dashboard (standalone shell with its own sidebar). The table shows saved records; KPIs and charts are sample data."""
    role = user_role(user)
    user = vuln_user(conn, user)
    name = (user["display_name"] or user["username"] or user["email"] or "").strip()
    parts = [p for p in re.split(r"[\s.]+", name) if p]
    initials = "".join(p[0] for p in parts[-2:]).upper() or "?"
    role_label = vuln_roles_text(user["_vrole"]) if user["_vrole"] else {ROLE_SUPERADMIN: "Супер админ"}.get(role, "Хэрэглэгч")
    dept_name = user["department_name"] or ""
    dept_slug = user["department_slug"] or ""
    if role == ROLE_SUPERADMIN or not dept_slug:
        assets_url = "/departments"
    else:
        assets_url = f"/departments/{quote(dept_slug)}/assets"
    scope = "" if vuln_perm(user, "view_all") else " · Надад хамаарах бүртгэл"
    page = VULN_DASHBOARD_TEMPLATE.read_text(encoding="utf-8")
    for key, value in (
        ("{{USER_NAME}}", name or "-"),
        ("{{USER_INITIALS}}", initials),
        ("{{USER_ROLE}}", role_label),
        ("{{ASSETS_URL}}", assets_url),
        ("{{SCOPE_LABEL}}", scope),
        ("{{NOTICE}}", notice),
        ("{{ERROR}}", error),
        ("{{TODAY}}", now_utc().date().isoformat()),
    ):
        page = page.replace(key, html.escape(value, quote=True))
    page = page.replace("{{SIDEBAR}}", _vulnreg_sidebar(conn, user, "dashboard"))
    # Inserted last so record text is never re-scanned for placeholders.
    return page.replace("{{VULN_ROWS_JSON}}", _script_json(list_vulnerabilities(conn, user)))


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
    can_edit = register["slug"] != INCIDENT_REGISTER_SLUG or incident_access(conn, user)[1]
    rows = conn.execute(f"SELECT * FROM {register['table']} ORDER BY id DESC").fetchall()
    body_rows = []
    for row in rows:
        cells = [f"<td>{row['id']}</td>"]
        for field_name, _ in columns:
            cells.append(f"<td>{format_multiline(row[field_name])}</td>")
        edit_html = (
            f'<a class="button-link ghost small" href="/admin-docs/registers/{html.escape(register["slug"])}/{row["id"]}/edit">Засах</a>'
            f'<form method="post" action="/admin-docs/registers/{html.escape(register["slug"])}/{row["id"]}/delete" class="inline-form"'
            ' onsubmit="return confirm(\'Устгахдаа итгэлтэй байна уу?\')">'
            '<button type="submit" class="link-button danger">Устгах</button></form>'
        ) if can_edit else ""
        cells.append(
            f"""
            <td class="table-actions">
              <div class="action-strip">
                <a class="button-link ghost small" href="/admin-docs/registers/{html.escape(register['slug'])}/{row['id']}">Дэлгэрэнгүй</a>
                {edit_html}
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
          {f'<a class="button-link" href="/admin-docs/registers/{html.escape(register["slug"])}/new">Мөр нэмэх</a>' if can_edit else ''}
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


def attachment_register_detail_page(user, register, entry, notice="", can_edit=True):
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
          {f'<a class="button-link ghost" href="/admin-docs/registers/{html.escape(register["slug"])}/{entry["id"]}/edit">Засах</a>' if can_edit else ''}
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


def insert_asset(conn, department_id, values):
    """Insert a validated asset (output of validate_asset_form) and return its id."""
    timestamp = now_utc().isoformat()
    cur = conn.execute(
        """
        INSERT INTO assets (
            department_id, asset_name, description, asset_type, asset_group_code,
            has_personal_data, has_sensitive_data, owner, custodian, location,
            retention_period, confidentiality, integrity_impact,
            availability_impact, asset_value, asset_category, review_frequency, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            department_id, values["asset_name"], values["description"], values["asset_type"], values["asset_group_code"],
            values["has_personal_data"], values["has_sensitive_data"], values["owner"], values["custodian"], values["location"],
            values["retention_period"], values["confidentiality"], values["integrity_impact"], values["availability_impact"],
            values["asset_value"], values["asset_category"], values.get("review_frequency", ""), timestamp, timestamp,
        ),
    )
    return cur.lastrowid


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

    if path.startswith("/static/") and path[len("/static/"):] in _VULNREG_STATIC:
        name = path[len("/static/"):]
        payload = (STATIC_DIR / name).read_bytes()
        start_response("200 OK", [("Content-Type", _VULNREG_STATIC[name]), ("Content-Length", str(len(payload))),
                                  ("Cache-Control", "no-cache")])
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

    if path == "/guide":
        page = guide_page(conn, user)
        conn.close()
        return response(start_response, "200 OK", page)

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
        parts = [unquote(part) for part in path.strip("/").split("/")]
        if len(parts) < 3:
            conn.close()
            return not_found(start_response)
        if parts[2] == INCIDENT_REGISTER_SLUG:
            # Incident Register: same rule as /incidents (Superadmin/InfoSec manage, Recipient/CTO read-only).
            inc_view, inc_manage = incident_access(conn, user)
            is_write = method != "GET" or parts[-1] in ("new", "edit")
            if not (inc_manage if is_write else inc_view):
                conn.close()
                return forbidden(start_response)
        elif not is_admin_or_above(user):
            conn.close()
            return forbidden(start_response)
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
            page = attachment_register_detail_page(user, register, entry, qs_value(query, "notice"),
                                                   can_edit=register["slug"] != INCIDENT_REGISTER_SLUG or incident_access(conn, user)[1])
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

    if path in ("/registry/vulnerabilities/dashboard", "/registry/vulnerabilities/dashboard/"):
        _vuln_prepare_conn(conn)
        user = vuln_user(conn, user)
        if not vuln_perm(user, "dashboard"):
            conn.close()
            return forbidden(start_response)
        page = vulnerability_dashboard_page(conn, user, qs_value(query, "notice"), qs_value(query, "error"))
        conn.close()
        return response(start_response, "200 OK", page)

    if path.startswith("/registry/vulnerabilities") and not path.startswith("/registry/vulnerabilities/dashboard"):
        _vuln_prepare_conn(conn)
        vpath = path.rstrip("/")
        is_api = vpath.startswith("/registry/vulnerabilities/api/")

        def _vdone(result):
            conn.close()
            return result

        # Server-side access control: only the roles granted access in Settings (or Superadmin) get in.
        user = vuln_user(conn, user)
        if not vuln_perm(user, "access"):
            if is_api:
                return _vdone(vuln_json(start_response, 403, {"error": "Эмзэг байдлын бүртгэлд хандах эрхгүй байна."}))
            return _vdone(forbidden(start_response))
        vuln_expire_sweep(conn)

        if vpath == "/registry/vulnerabilities" and method == "GET":
            page = _vulnreg_page(conn, user, VULN_LIST_TEMPLATE, "vulns", {})
            return _vdone(response(start_response, "200 OK", page))

        if vpath == "/registry/vulnerabilities/export" and method == "GET":
            if not vuln_perm(user, "export"):
                return _vdone(forbidden(start_response))
            fmt = "xlsx" if qs_value(query, "format") == "xlsx" else "csv"
            payload, ctype, fname = vuln_export(conn, user, query, fmt)
            return _vdone(send_bytes(start_response, payload, ctype, fname))

        if vpath == "/registry/vulnerabilities/settings" and method == "GET":
            if not vuln_can_view_settings(user):
                return _vdone(forbidden(start_response))
            page = _vulnreg_page(conn, user, VULN_SETTINGS_TEMPLATE, "settings", {})
            return _vdone(response(start_response, "200 OK", page))

        if vpath == "/registry/vulnerabilities/api/settings" and method == "GET":
            code, body = vuln_api_settings(conn, user)
            return _vdone(vuln_json(start_response, code, body))

        if vpath == "/registry/vulnerabilities/api/settings" and method == "POST":
            code, body = vuln_api_settings_save(conn, user, parse_post(environ))
            return _vdone(vuln_json(start_response, code, body))

        if vpath == "/registry/vulnerabilities/api/settings/recalc" and method == "POST":
            code, body = vuln_api_settings_recalc(conn, user, parse_post(environ))
            return _vdone(vuln_json(start_response, code, body))

        if vpath == "/registry/vulnerabilities/api/list" and method == "GET":
            return _vdone(vuln_json(start_response, 200, vuln_api_list(conn, user, query)))

        if vpath == "/registry/vulnerabilities/api/options" and method == "GET":
            return _vdone(vuln_json(start_response, 200, vuln_api_options(conn, user)))

        if vpath == "/registry/vulnerabilities/api/assets/create" and method == "POST":
            code, body = vuln_api_create_asset(conn, user, parse_post(environ))
            return _vdone(vuln_json(start_response, code, body))

        if vpath == "/registry/vulnerabilities/api/create" and method == "POST":
            code, body = vuln_api_create(conn, user, parse_post(environ))
            return _vdone(vuln_json(start_response, code, body))

        m = re.fullmatch(r"/registry/vulnerabilities/(?:api/)?(\d+)(/.*)?", vpath)
        if m:
            row = vuln_get(conn, user, int(m.group(1)))
            sub = m.group(2) or ""
            if not row:
                if is_api:
                    return _vdone(vuln_json(start_response, 404, {"error": "Бүртгэл олдсонгүй эсвэл харах эрхгүй."}))
                return _vdone(not_found(start_response))
            if not is_api:
                if sub == "" and method == "GET":
                    page = _vulnreg_page(conn, user, VULN_DETAIL_TEMPLATE, "vulns", {"id": row["id"]})
                    return _vdone(response(start_response, "200 OK", page))
                fm = re.fullmatch(r"/files/(\d+)", sub)
                if fm and method == "GET":
                    frow = vuln_file_row(conn, row, int(fm.group(1)))
                    fpath = (VULN_FILES_DIR / frow["stored_name"]).resolve() if frow else None
                    if not frow or not fpath.is_file() or fpath.parent != VULN_FILES_DIR.resolve():
                        return _vdone(not_found(start_response))
                    record_audit(conn, user["id"], "download", "vulnerability", entity_id=row["id"],
                                 department_id=row["department_id"], details=f"{_vuln_ref(row)} нотлох баримт татав: {frow['original_name']}")
                    conn.commit()
                    return _vdone(send_file(start_response, fpath, frow["original_name"]))
                return _vdone(not_found(start_response))
            if sub == "" and method == "GET":
                return _vdone(vuln_json(start_response, 200, vuln_api_detail(conn, user, row)))
            if method != "POST":
                return _vdone(vuln_json(start_response, 400, {"error": "Буруу хүсэлт."}))
            if sub == "/files":
                # Multipart bodies skip the global CSRF check, so verify the token here.
                form = parse_multipart(environ)
                if not hmac.compare_digest(_csrf_token() or "-", form.getfirst("_csrf", "") or ""):
                    return _vdone(vuln_json(start_response, 403, {"error": "CSRF токен буруу. Хуудсаа дахин ачаална уу."}))
                code, body = vuln_api_upload(conn, user, row, form)
                return _vdone(vuln_json(start_response, code, body))
            form = parse_post(environ)
            if sub == "/update":
                code, body = vuln_api_update(conn, user, row, form)
            elif sub == "/action":
                code, body = vuln_api_action(conn, user, row, form)
            elif sub == "/assign":
                code, body = vuln_api_assign(conn, user, row, form)
            elif sub == "/comment":
                code, body = vuln_api_comment(conn, user, row, form)
            elif sub == "/delete":
                code, body = vuln_api_delete(conn, user, row, form)
            else:
                fm = re.fullmatch(r"/files/(\d+)/delete", sub)
                frow = vuln_file_row(conn, row, int(fm.group(1))) if fm else None
                if not frow:
                    return _vdone(vuln_json(start_response, 404, {"error": "Файл олдсонгүй."}))
                code, body = vuln_api_file_delete(conn, user, row, frow)
            return _vdone(vuln_json(start_response, code, body))

        if is_api:
            return _vdone(vuln_json(start_response, 404, {"error": "Олдсонгүй."}))
        return _vdone(not_found(start_response))

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
        new_role, new_vuln_roles = role_level_from_form(form)
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
        if new_vuln_roles:
            ensure_vulnerabilities_table(conn)  # adds users.vuln_role (the service does not run ensure_database())
            conn.execute("UPDATE users SET vuln_role = ?, is_it_head = ? WHERE id = ?",
                         (vuln_roles_value(new_vuln_roles), 1 if "receiver" in new_vuln_roles else 0, new_user_id))
            new_row = conn.execute("SELECT * FROM users WHERE id = ?", (new_user_id,)).fetchone()
            _vuln_config_log(conn, user, f"user_role:{new_user_id}", f"Эрх — {_vuln_user_label(new_row)}",
                             VULN_ROLE_LABELS[""], vuln_roles_text(new_vuln_roles),
                             "Шинэ хэрэглэгч үүсгэх үед олгосон (Хэрэглэгчид → Хэрэглэгч нэмэх).")
        conn.execute("UPDATE users SET last_invited_at = ? WHERE id = ?", (timestamp, new_user_id))
        send_invitation_email(conn, new_user_id, email, display_name)
        conn.commit()
        conn.close()
        return redirect(start_response, "/users?notice=" + quote(f"{email} хэрэглэгч үүсгэж урилга илгээлээ."))

    if path.startswith("/users/") and path.endswith("/edit"):
        if not can_manage_users(user):
            conn.close()
            return forbidden(start_response)
        ensure_vulnerabilities_table(conn)  # adds users.vuln_role (the service does not run ensure_database())
        target_id = path.strip("/").split("/")[1]
        target_user = get_user_with_department(conn, target_id)
        if not target_user:
            conn.close()
            return not_found(start_response)
        all_departments = list(conn.execute("SELECT * FROM departments ORDER BY name"))
        dept_perms = get_user_dept_perms(conn, target_user["id"])
        label = target_user["display_name"] or target_user["email"] or target_user["username"]
        if method == "GET":
            page = render_page(f"{label} — Засах", user, user_edit_page(conn, target_user, all_departments, dept_perms,
                                                                        lock_sys=target_user["id"] == user["id"]))
            conn.close()
            return response(start_response, "200 OK", page)
        form = parse_post(environ)
        email = (form.get("email") or "").strip().lower()
        display_name = (form.get("display_name") or "").strip()
        dept_id = form.get("department_id") or None
        new_role, new_vuln_roles = role_level_from_form(form)
        role_reason = (form.get("role_reason") or "").strip()[:2000]
        old_role = user_role(target_user)
        old_vuln_roles = vuln_roles_of(target_user)
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
        if new_vuln_roles != old_vuln_roles:
            conn.execute("UPDATE users SET vuln_role = ?, is_it_head = ? WHERE id = ?",
                         (vuln_roles_value(new_vuln_roles), 1 if "receiver" in new_vuln_roles else 0, target_user["id"]))
        log_role_change(conn, user, target_user, old_role, new_role, old_vuln_roles, new_vuln_roles, role_reason)
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
            asset_id = insert_asset(conn, department["id"], values)
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
