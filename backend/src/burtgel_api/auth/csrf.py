import hmac
import hashlib

from burtgel_api.config import settings

CSRF_HEADER = "x-csrf-token"


def csrf_token_for_session(session_id: str) -> str:
    return hmac.new(settings.secret_key.encode(), session_id.encode(), hashlib.sha256).hexdigest()[:32]


def verify_csrf(session_id: str | None, submitted: str | None) -> bool:
    if not session_id or not submitted:
        return False
    expected = csrf_token_for_session(session_id)
    return hmac.compare_digest(expected, submitted)
