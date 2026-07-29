from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column


from burtgel_api.db.base import Base


class DepartmentColumnPermission(Base):
    __tablename__ = "department_column_permissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id", ondelete="CASCADE"))
    field_name: Mapped[str] = mapped_column(String)
    can_edit: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[str] = mapped_column(String)
    updated_at: Mapped[str] = mapped_column(String)


class UserDepartmentPermission(Base):
    __tablename__ = "user_department_permissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id", ondelete="CASCADE"))
    can_read: Mapped[int] = mapped_column(default=0)
    can_update: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[str] = mapped_column(String)
    updated_at: Mapped[str] = mapped_column(String)
