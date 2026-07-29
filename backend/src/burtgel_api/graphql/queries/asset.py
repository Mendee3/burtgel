import strawberry
from strawberry.types import Info

from burtgel_api.auth.permissions import can_access_department, can_update_in_department
from burtgel_api.db.models import Asset, Department
from burtgel_api.graphql.require_login import require_login
from burtgel_api.graphql.types import AssetType, AssetPermissions
from burtgel_api.graphql.types.asset import AssetConnection
from burtgel_api.graphql.converters import to_asset_type
from burtgel_api.services.asset_service import editable_fields_for, get_department_permissions


def _get_department_or_raise(db, department_slug: str) -> Department:
    department = db.query(Department).filter(Department.slug == department_slug).one_or_none()
    if department is None:
        raise Exception("Хэлтэс олдсонгүй.")
    return department


@strawberry.type
class AssetQuery:
    @strawberry.field
    def assets(self, info: Info, department_slug: str, search: str | None = None) -> AssetConnection:
        user = require_login(info)
        db = info.context.db
        department = _get_department_or_raise(db, department_slug)
        if not can_access_department(user, department, db):
            raise Exception("Энэ хэлтсийн мэдээлэлд хандах эрхгүй байна.")

        query = db.query(Asset).filter(Asset.department_id == department.id)
        if search:
            like = f"%{search}%"
            query = query.filter(Asset.asset_name.ilike(like))

        rows = query.order_by(Asset.asset_name).all()
        return AssetConnection(items=[to_asset_type(a) for a in rows], total_count=len(rows))

    @strawberry.field
    def asset_permissions(self, info: Info, department_slug: str) -> AssetPermissions:
        user = require_login(info)
        db = info.context.db
        department = _get_department_or_raise(db, department_slug)
        can_read = can_access_department(user, department, db)
        can_update = can_read and can_update_in_department(user, department, db)
        permissions = get_department_permissions(db, department.id)
        editable = editable_fields_for(user, permissions) if can_update else []
        return AssetPermissions(can_read=can_read, can_update=can_update, editable_fields=editable)
