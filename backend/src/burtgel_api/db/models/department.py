from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from burtgel_api.db.base import Base


class Department(Base):
    __tablename__ = "departments"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String, unique=True)
    slug: Mapped[str] = mapped_column(String, unique=True)
    name: Mapped[str] = mapped_column(String)

    assets: Mapped[list["Asset"]] = relationship(back_populates="department")
