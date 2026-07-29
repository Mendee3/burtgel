from strawberry.types import Info

from burtgel_api.db.models import User


def require_login(info: Info) -> User:
    user = info.context.current_user
    if not user:
        raise Exception("Нэвтрэх шаардлагатай.")
    return user
