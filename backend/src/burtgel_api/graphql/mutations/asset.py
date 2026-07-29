import strawberry
from strawberry.types import Info

from burtgel_api.auth.permissions import can_update_in_department
from burtgel_api.auth.sessions import now_utc
from burtgel_api.db.models import Asset, Department
from burtgel_api.graphql.converters import to_asset_type
from burtgel_api.graphql.require_login import require_login
from burtgel_api.graphql.types import MutationResult
from burtgel_api.graphql.types.asset import AssetInput, AssetResult, ValidationError
from burtgel_api.services.asset_service import ASSET_FIELDS, get_department_permissions, validate_asset_form
from burtgel_api.services.audit_service import record_audit

ASSET_FIELD_NAMES = [field for field, _, _ in ASSET_FIELDS]


def _asset_to_dict(asset: Asset) -> dict[str, str]:
    return {field: getattr(asset, field, "") for field in ASSET_FIELD_NAMES} | {
        "review_frequency": asset.review_frequency
    }


def _require_department_and_update_access(info: Info, department_slug: str) -> tuple[Department, dict]:
    user = require_login(info)
    db = info.context.db
    department = db.query(Department).filter(Department.slug == department_slug).one_or_none()
    if department is None:
        raise Exception("Хэлтэс олдсонгүй.")
    if not can_update_in_department(user, department, db):
        raise Exception("Энэ хэлтсийн мэдээлэл засах эрхгүй байна.")
    if not info.context.csrf_ok():
        raise Exception("Хүсэлт хүчингүй байна. Дахин ачаална уу.")
    return department, get_department_permissions(db, department.id)


@strawberry.type
class AssetMutation:
    @strawberry.mutation
    def create_asset(self, info: Info, department_slug: str, input: AssetInput) -> AssetResult:
        user = info.context.current_user
        department, permissions = _require_department_and_update_access(info, department_slug)
        db = info.context.db

        form = strawberry.asdict(input)
        values, error = validate_asset_form(form, user, permissions)
        if error:
            return ValidationError(message=error)

        timestamp = now_utc().isoformat()
        asset = Asset(department_id=department.id, created_at=timestamp, updated_at=timestamp, **values)
        db.add(asset)
        db.flush()
        record_audit(
            db, user.id, "create", "asset", entity_id=asset.id, department_id=department.id,
            details=f"{asset.asset_name} хөрөнгө үүслээ.",
        )
        db.commit()
        return to_asset_type(asset)

    @strawberry.mutation
    def update_asset(self, info: Info, department_slug: str, id: strawberry.ID, input: AssetInput) -> AssetResult:
        user = info.context.current_user
        department, permissions = _require_department_and_update_access(info, department_slug)
        db = info.context.db

        asset = db.query(Asset).filter(Asset.id == int(id), Asset.department_id == department.id).one_or_none()
        if asset is None:
            return ValidationError(message="Хөрөнгө олдсонгүй.")

        form = strawberry.asdict(input)
        values, error = validate_asset_form(form, user, permissions, existing_asset=_asset_to_dict(asset))
        if error:
            return ValidationError(message=error)

        for field, value in values.items():
            setattr(asset, field, value)
        asset.updated_at = now_utc().isoformat()
        record_audit(
            db, user.id, "update", "asset", entity_id=asset.id, department_id=department.id,
            details=f"{asset.asset_name} хөрөнгө шинэчлэгдлээ.",
        )
        db.commit()
        return to_asset_type(asset)

    @strawberry.mutation
    def delete_asset(self, info: Info, department_slug: str, id: strawberry.ID) -> MutationResult:
        user = info.context.current_user
        department, _permissions = _require_department_and_update_access(info, department_slug)
        db = info.context.db

        asset = db.query(Asset).filter(Asset.id == int(id), Asset.department_id == department.id).one_or_none()
        if asset is None:
            return MutationResult(success=False, message="Хөрөнгө олдсонгүй.")

        asset_name = asset.asset_name
        db.delete(asset)
        record_audit(
            db, user.id, "delete", "asset", entity_id=id, department_id=department.id,
            details=f"{asset_name} хөрөнгө устгагдлаа.",
        )
        db.commit()
        return MutationResult(success=True, message="Хөрөнгө устгагдлаа.")
