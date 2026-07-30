import datetime as dt

from sqlalchemy.orm import Session as DbSession

from burtgel_api.auth.sessions import now_utc
from burtgel_api.db.models import Incident

INCIDENT_FIELDS = [
    ("detected_date", "Огноо (илэрсэн)", True),
    ("occurred_date", "Үүссэн (таамаг)", False),
    ("reported_by", "Мэдээлсэн", False),
    ("system_location", "Систем / Байршил", False),
    ("incident_type", "Төрөл", False),
    ("severity", "Severity", False),
    ("l1_started", "L1 эхэлсэн", False),
    ("l2", "L2", False),
    ("l3", "L3", False),
    ("closed", "Хаасан", False),
    ("resolution_time", "Шийдвэрлэх хугацаа", False),
    ("sla_violated", "SLA зөрчсөн", False),
    ("root_cause", "Root Cause", False),
    ("description", "Тайлбар", False),
]

SEVERITY_OPTIONS = ["Бага", "Дунд", "Өндөр", "Маш Өндөр"]
SLA_OPTIONS = ["Тийм", "Үгүй"]


def normalize_text(value) -> str:
    if value is None:
        return ""
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()


def generate_incident_id(db: DbSession) -> str:
    year = now_utc().year
    count = (
        db.query(Incident)
        .filter(Incident.created_at.like(f"{year}-%"))
        .count()
    )
    return f"INC-{year}-{(count + 1):03d}"


def validate_incident_form(form: dict[str, str]) -> tuple[dict[str, str] | None, str]:
    values: dict[str, str] = {}
    for field, label, required in INCIDENT_FIELDS:
        value = normalize_text(form.get(field))
        if field == "severity" and value and value not in SEVERITY_OPTIONS:
            return None, f"{label} талбарын утга буруу байна."
        if field == "sla_violated" and value and value not in SLA_OPTIONS:
            return None, f"{label} талбарын утга буруу байна."
        if required and not value:
            return None, f"{label} талбарыг бөглөнө үү."
        values[field] = value
    return values, ""


# Upper bound of each severity's response/resolution window (hours), used as the hard deadline.
SEVERITY_DEADLINE_HOURS = {
    "Маш Өндөр": 6,
    "Өндөр": 12,
    "Дунд": 48,
    "Бага": 72,
}
DEFAULT_DEADLINE_HOURS = 72

STATUS_OPEN = "Нээлттэй"
STATUS_ACTION_TAKEN = "Хариу арга хэмжээ авсан"
STATUS_CLOSED = "Хаагдсан"


def _parse_dt(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def deadline_hours_for_severity(severity: str) -> int:
    return SEVERITY_DEADLINE_HOURS.get(severity, DEFAULT_DEADLINE_HOURS)


def compute_deadline(
    severity: str, created_at: str, reference_at: str | None = None, force_not_overdue: bool = False
) -> dict:
    hours = deadline_hours_for_severity(severity)
    registered_at = _parse_dt(created_at)
    deadline_at = registered_at + dt.timedelta(hours=hours)
    reference = _parse_dt(reference_at) if reference_at else now_utc()
    remaining = (deadline_at - reference).total_seconds()
    is_overdue = remaining < 0
    if force_not_overdue and is_overdue:
        # Manually closed past its deadline: don't show a misleading "time remaining"
        # figure (the raw negative value), just clamp to zero.
        is_overdue = False
        remaining = 0
    return {
        "deadline_at": deadline_at.isoformat(),
        "hours_allowed": hours,
        "is_overdue": is_overdue,
        "remaining_seconds": int(remaining),
    }


def compute_incident_status(severity: str, closed: str, created_at: str, has_corrective_action: bool) -> str:
    if closed:
        return STATUS_CLOSED
    if has_corrective_action:
        return STATUS_ACTION_TAKEN
    if compute_deadline(severity, created_at)["is_overdue"]:
        # Deadline expired with no corrective action: system auto-closes it.
        return STATUS_CLOSED
    return STATUS_OPEN
