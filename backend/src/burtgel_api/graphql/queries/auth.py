import strawberry
from strawberry.types import Info

from burtgel_api.auth.csrf import csrf_token_for_session
from burtgel_api.graphql.converters import to_user_type
from burtgel_api.graphql.types import UserType


@strawberry.type
class AuthQuery:
    @strawberry.field
    def me(self, info: Info) -> UserType | None:
        user = info.context.current_user
        return to_user_type(user) if user else None

    @strawberry.field
    def csrf_token(self, info: Info) -> str:
        session_id = info.context.session_id
        return csrf_token_for_session(session_id) if session_id else ""
