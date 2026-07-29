from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from burtgel_api.db.base import Base


class IncidentCorrectiveAction(Base):
    __tablename__ = "incident_corrective_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("attachment_incidents.id", ondelete="CASCADE"))
    description: Mapped[str] = mapped_column(String)
    added_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    added_by_name: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[str] = mapped_column(String)


class IncidentSeverityChange(Base):
    __tablename__ = "incident_severity_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("attachment_incidents.id", ondelete="CASCADE"))
    previous_severity: Mapped[str] = mapped_column(String)
    new_severity: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(String)
    changed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    changed_by_name: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[str] = mapped_column(String)
