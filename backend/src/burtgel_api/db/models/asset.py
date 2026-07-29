from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from burtgel_api.db.base import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id", ondelete="CASCADE"))
    asset_name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    asset_type: Mapped[str] = mapped_column(String)
    asset_group_code: Mapped[str] = mapped_column(String)
    has_personal_data: Mapped[str] = mapped_column(String)
    has_sensitive_data: Mapped[str] = mapped_column(String)
    owner: Mapped[str] = mapped_column(String)
    custodian: Mapped[str] = mapped_column(String)
    location: Mapped[str] = mapped_column(String)
    access_right: Mapped[str] = mapped_column(String, default="")
    retention_period: Mapped[str] = mapped_column(String, default="")
    confidentiality: Mapped[str] = mapped_column(String, default="")
    integrity_impact: Mapped[str] = mapped_column(String, default="")
    availability_impact: Mapped[str] = mapped_column(String, default="")
    asset_value: Mapped[str] = mapped_column(String, default="")
    asset_category: Mapped[str] = mapped_column(String, default="")
    review_frequency: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[str] = mapped_column(String)
    updated_at: Mapped[str] = mapped_column(String)

    department: Mapped["Department"] = relationship(back_populates="assets")
