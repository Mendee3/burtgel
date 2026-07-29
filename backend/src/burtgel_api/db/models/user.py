from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from burtgel_api.db.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    password_hash: Mapped[str] = mapped_column(String)
    department_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id", ondelete="SET NULL"))
    is_admin: Mapped[int] = mapped_column(default=0)
    is_active: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[str] = mapped_column(String)
    last_login_at: Mapped[str | None] = mapped_column(String)
    must_change_password: Mapped[int] = mapped_column(default=0)
    password_changed_at: Mapped[str | None] = mapped_column(String)
    email: Mapped[str | None] = mapped_column(String)
    display_name: Mapped[str] = mapped_column(String, default="")
    role: Mapped[str] = mapped_column(String, default="user")
    last_invited_at: Mapped[str | None] = mapped_column(String)

    department: Mapped["Department | None"] = relationship()


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[str] = mapped_column(String)
    last_active_at: Mapped[str | None] = mapped_column(String)
