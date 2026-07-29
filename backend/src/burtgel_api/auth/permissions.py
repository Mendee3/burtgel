from sqlalchemy.orm import Session as DbSession

from burtgel_api.db.models import Department, User, UserDepartmentPermission

ROLE_SUPERADMIN = "superadmin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"


def user_role(user: User | None) -> str:
    if not user:
        return ROLE_USER
    return user.role or ROLE_USER


def is_superadmin(user: User | None) -> bool:
    return user_role(user) == ROLE_SUPERADMIN


def is_admin_or_above(user: User | None) -> bool:
    return user_role(user) in (ROLE_SUPERADMIN, ROLE_ADMIN)


def can_manage_users(user: User | None) -> bool:
    return is_superadmin(user)


def password_setup_required(user: User | None) -> bool:
    return bool(user and user.must_change_password)


def departments_for_user(db: DbSession, user: User) -> list[Department]:
    if is_admin_or_above(user):
        return db.query(Department).order_by(Department.name).all()
    dept_ids: set[int] = set()
    if user.department_id:
        dept_ids.add(user.department_id)
    rows = (
        db.query(UserDepartmentPermission.department_id)
        .filter(UserDepartmentPermission.user_id == user.id, UserDepartmentPermission.can_read == 1)
        .all()
    )
    dept_ids.update(r[0] for r in rows)
    if not dept_ids:
        return []
    return db.query(Department).filter(Department.id.in_(dept_ids)).order_by(Department.name).all()


def can_access_department(user: User | None, department: Department | None, db: DbSession | None = None) -> bool:
    if not (user and department):
        return False
    if is_admin_or_above(user):
        return True
    if user.department_id == department.id:
        return True
    if db is not None:
        row = (
            db.query(UserDepartmentPermission)
            .filter_by(user_id=user.id, department_id=department.id, can_read=1)
            .first()
        )
        return row is not None
    return False


def can_update_in_department(user: User | None, department: Department | None, db: DbSession | None = None) -> bool:
    if not (user and department):
        return False
    if is_admin_or_above(user):
        return True
    if db is not None:
        row = db.query(UserDepartmentPermission).filter_by(user_id=user.id, department_id=department.id).first()
        if row is not None:
            return bool(row.can_update)
    return user.department_id == department.id


def can_edit_field(user: User | None, permissions: dict[str, bool], field_name: str) -> bool:
    return bool(user and (is_admin_or_above(user) or permissions.get(field_name, True)))
