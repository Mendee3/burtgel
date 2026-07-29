from dataclasses import dataclass, field

from fastapi import Depends, Request, Response
from sqlalchemy.orm import Session as DbSession
from strawberry.fastapi import BaseContext

from burtgel_api.auth.csrf import verify_csrf
from burtgel_api.auth.sessions import (
    SESSION_COOKIE,
    create_session,
    get_current_user,
    sign_cookie,
    verify_signed_cookie,
)
from burtgel_api.db.models import User
from burtgel_api.db.session import get_db_session

# TEMPORARY: bypasses the username/email + password login requirement — any
# request with no active session is auto-logged-in as DEV_AUTH_BYPASS_USERNAME.
# Set to False to restore the normal login requirement.
DEV_AUTH_BYPASS_ENABLED = False
DEV_AUTH_BYPASS_USERNAME = "b.ganbat"
_SESSION_COOKIE_MAX_AGE = 7 * 24 * 60 * 60


@dataclass
class GraphQLContext(BaseContext):
    db: DbSession
    request: Request
    response: Response
    _user: User | None = field(default=None, repr=False)
    _user_loaded: bool = field(default=False, repr=False)
    _session_id: str | None = field(default=None, repr=False)
    _session_id_loaded: bool = field(default=False, repr=False)

    @property
    def session_id(self) -> str | None:
        if not self._session_id_loaded:
            raw = self.request.cookies.get(SESSION_COOKIE)
            self._session_id = verify_signed_cookie(raw) if raw else None
            self._session_id_loaded = True
        return self._session_id

    @property
    def current_user(self) -> User | None:
        if not self._user_loaded:
            user = get_current_user(self.db, self.session_id)
            if user is None and DEV_AUTH_BYPASS_ENABLED:
                user = self._dev_auto_login()
            self._user = user
            self._user_loaded = True
        return self._user

    def _dev_auto_login(self) -> User | None:
        user = (
            self.db.query(User)
            .filter(User.username == DEV_AUTH_BYPASS_USERNAME, User.is_active == 1)
            .one_or_none()
        )
        if user is None:
            user = self.db.query(User).filter(User.is_active == 1).order_by(User.id).first()
        if user is None:
            return None
        session_id = create_session(self.db, user.id)
        self.response.set_cookie(
            key=SESSION_COOKIE,
            value=sign_cookie(session_id),
            max_age=_SESSION_COOKIE_MAX_AGE,
            path="/",
            httponly=True,
            samesite="lax",
        )
        self._session_id = session_id
        self._session_id_loaded = True
        return user

    def csrf_ok(self) -> bool:
        return verify_csrf(self.session_id, self.request.headers.get("x-csrf-token"))


async def get_context(
    request: Request, response: Response, db: DbSession = Depends(get_db_session)
) -> GraphQLContext:
    return GraphQLContext(db=db, request=request, response=response)
