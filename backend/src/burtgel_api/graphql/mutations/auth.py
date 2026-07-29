import strawberry
from strawberry.types import Info

from burtgel_api.auth.csrf import csrf_token_for_session
from burtgel_api.auth.passwords import hash_password, validate_password_policy, verify_password
from burtgel_api.auth.sessions import SESSION_COOKIE, clear_session, create_session, now_utc, sign_cookie
from burtgel_api.db.models import User
from burtgel_api.graphql.converters import to_user_type
from burtgel_api.graphql.require_login import require_login
from burtgel_api.graphql.types import LoginResult, MutationResult

COOKIE_MAX_AGE = 7 * 24 * 60 * 60


def _set_session_cookie(response, session_id: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=sign_cookie(session_id),
        max_age=COOKIE_MAX_AGE,
        path="/",
        httponly=True,
        samesite="lax",
    )


@strawberry.type
class AuthMutation:
    @strawberry.mutation
    def login(self, info: Info, username: str, password: str) -> LoginResult:
        db = info.context.db
        identifier = username.strip().lower()
        user = (
            db.query(User)
            .filter(User.is_active == 1)
            .filter((User.username.ilike(identifier)) | (User.email.ilike(identifier)))
            .one_or_none()
        )
        if not user or not verify_password(password, user.password_hash):
            return LoginResult(success=False, message="И-мэйл/хэрэглэгчийн нэр эсвэл нууц үг буруу байна.")

        user.last_login_at = now_utc().isoformat()
        session_id = create_session(db, user.id)
        _set_session_cookie(info.context.response, session_id)
        return LoginResult(
            success=True, message="", user=to_user_type(user), csrf_token=csrf_token_for_session(session_id)
        )

    @strawberry.mutation
    def logout(self, info: Info) -> bool:
        clear_session(info.context.db, info.context.session_id)
        info.context.response.delete_cookie(key=SESSION_COOKIE, path="/")
        return True

    @strawberry.mutation
    def change_password(self, info: Info, current_password: str, new_password: str) -> MutationResult:
        user = require_login(info)
        if not info.context.csrf_ok():
            return MutationResult(success=False, message="Хүсэлт хүчингүй байна. Дахин ачаална уу.")
        if not verify_password(current_password, user.password_hash):
            return MutationResult(success=False, message="Одоогийн нууц үг буруу байна.")
        policy_error = validate_password_policy(new_password)
        if policy_error:
            return MutationResult(success=False, message=policy_error)

        db = info.context.db
        user.password_hash = hash_password(new_password)
        user.password_changed_at = now_utc().isoformat()
        user.must_change_password = 0
        db.commit()
        return MutationResult(success=True, message="Нууц үг амжилттай солигдлоо.")
