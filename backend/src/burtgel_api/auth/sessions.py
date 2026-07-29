import datetime as dt
import hashlib
import hmac
import secrets
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session as DbSession

from burtgel_api.config import settings
from burtgel_api.db.models import Session as SessionModel
from burtgel_api.db.models import User

SESSION_COOKIE = "burtgel_session"
SESSION_ABSOLUTE_EXPIRY_DAYS = 7
SESSION_INACTIVITY_TIMEOUT_MINUTES = 60
_TZ = ZoneInfo("Asia/Ulaanbaatar")


def now_utc() -> dt.datetime:
    return dt.datetime.now(_TZ).replace(microsecond=0)


def _parse_dt(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def sign_cookie(value: str) -> str:
    signature = hmac.new(settings.secret_key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{signature}"


def verify_signed_cookie(value: str) -> str | None:
    try:
        raw, signature = value.rsplit(".", 1)
    except ValueError:
        return None
    expected = hmac.new(settings.secret_key.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(signature, expected):
        return raw
    return None


def create_session(db: DbSession, user_id: int) -> str:
    session_id = secrets.token_urlsafe(32)
    now = now_utc()
    expires_at = now + dt.timedelta(days=SESSION_ABSOLUTE_EXPIRY_DAYS)
    db.add(SessionModel(id=session_id, user_id=user_id, expires_at=expires_at.isoformat(), last_active_at=now.isoformat()))
    db.commit()
    return session_id


def get_current_user(db: DbSession, session_id: str | None) -> User | None:
    if not session_id:
        return None
    session_row = db.get(SessionModel, session_id)
    if not session_row:
        return None
    now = now_utc()
    if _parse_dt(session_row.expires_at) < now:
        db.delete(session_row)
        db.commit()
        return None
    if session_row.last_active_at and (now - _parse_dt(session_row.last_active_at)) > dt.timedelta(
        minutes=SESSION_INACTIVITY_TIMEOUT_MINUTES
    ):
        db.delete(session_row)
        db.commit()
        return None
    user = db.get(User, session_row.user_id)
    if not user or not user.is_active:
        return None
    session_row.last_active_at = now.isoformat()
    db.commit()
    return user


def clear_session(db: DbSession, session_id: str | None) -> None:
    if not session_id:
        return
    session_row = db.get(SessionModel, session_id)
    if session_row:
        db.delete(session_row)
        db.commit()
