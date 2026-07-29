from sqlalchemy.orm import Session as DbSession

from burtgel_api.auth.permissions import can_edit_field, is_admin_or_above
from burtgel_api.db.models import DepartmentColumnPermission, User

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

DROPDOWN_OPTIONS: dict[str, list] = {
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

ASSET_COMPUTED_FIELDS = {"asset_value", "asset_category"}
FREQUENCY_OPTIONS = ["Сараар", "Улирлаар", "Хагас жилээр", "Жилээр"]


def normalize_text(value) -> str:
    if value is None:
        return ""
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()


def normalize_flag(value) -> str:
    text = normalize_text(value).upper()
    if text in {"Y", "YES"}:
        return "Y"
    if text in {"N", "NO"}:
        return "N"
    return text


def compute_asset_value(confidentiality: str, integrity_impact: str, availability_impact: str) -> str:
    c = ASSET_SCORE_MAP.get(confidentiality, 0)
    i = ASSET_SCORE_MAP.get(integrity_impact, 0)
    a = ASSET_SCORE_MAP.get(availability_impact, 0)
    if not (c and i and a):
        return ""
    return str(c + i + a)


def compute_asset_category(asset_value: str) -> str:
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


def get_department_permissions(db: DbSession, department_id: int) -> dict[str, bool]:
    rows = db.query(DepartmentColumnPermission).filter_by(department_id=department_id).all()
    permissions = {row.field_name: bool(row.can_edit) for row in rows}
    for field_name, _, _ in ASSET_FIELDS:
        permissions.setdefault(field_name, True)
    return permissions


def editable_fields_for(user: User, permissions: dict[str, bool]) -> list[str]:
    return [field for field, _, _ in ASSET_FIELDS if field not in ASSET_COMPUTED_FIELDS and can_edit_field(user, permissions, field)]


def validate_asset_form(
    form: dict[str, str], user: User, permissions: dict[str, bool], existing_asset: dict[str, str] | None = None
) -> tuple[dict[str, str] | None, str]:
    values: dict[str, str] = {}
    for field, label, required in ASSET_FIELDS:
        if field in ASSET_COMPUTED_FIELDS:
            continue
        editable = can_edit_field(user, permissions, field)
        if editable:
            value = normalize_text(form.get(field))
            if field in {"has_personal_data", "has_sensitive_data"}:
                value = normalize_flag(value)
            if field in DROPDOWN_OPTIONS and value:
                valid_values = {(o[1] if isinstance(o, tuple) else o) for o in DROPDOWN_OPTIONS[field]}
                if value not in valid_values:
                    return None, f"{label} талбарын утга буруу байна."
        else:
            value = normalize_text((existing_asset or {}).get(field))
        if required and editable and not value:
            return None, f"{label} талбарыг бөглөнө үү."
        values[field] = value

    asset_val = compute_asset_value(
        values.get("confidentiality", ""), values.get("integrity_impact", ""), values.get("availability_impact", "")
    )
    values["asset_value"] = asset_val
    values["asset_category"] = compute_asset_category(asset_val)

    if is_admin_or_above(user):
        freq = normalize_text(form.get("review_frequency"))
        if freq and freq not in FREQUENCY_OPTIONS:
            return None, f"Хянах давтамжийн утга буруу байна: {freq}"
        values["review_frequency"] = freq
    else:
        values["review_frequency"] = normalize_text((existing_asset or {}).get("review_frequency", ""))

    return values, ""
