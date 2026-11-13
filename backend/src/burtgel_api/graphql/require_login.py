from strawberry.types import Info

from burtgel_api.auth.incident_access import incident_access
from burtgel_api.db.models import User


def require_incident_view(info: Info) -> User:
    user = require_login(info)
    if not incident_access(info.context.db, user)[0]:
        raise Exception("Зөрчлийн бүртгэлд хандах эрхгүй байна.")
    return user


def require_incident_manage(info: Info) -> User:
    user = require_login(info)
    if not incident_access(info.context.db, user)[1]:
        raise Exception("Зөрчлийн бүртгэлд өөрчлөлт хийх эрхгүй байна.")
    return user


def require_login(info: Info) -> User:
    user = info.context.current_user
    if not user:
        raise Exception("Нэвтрэх шаардлагатай.")
    return user
