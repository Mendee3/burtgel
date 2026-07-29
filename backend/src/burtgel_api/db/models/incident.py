from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from burtgel_api.db.base import Base


class Incident(Base):
    __tablename__ = "attachment_incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, default="")
    detected_date: Mapped[str] = mapped_column(String, default="")
    occurred_date: Mapped[str] = mapped_column(String, default="")
    reported_by: Mapped[str] = mapped_column(String, default="")
    system_location: Mapped[str] = mapped_column(String, default="")
    incident_type: Mapped[str] = mapped_column(String, default="")
    severity: Mapped[str] = mapped_column(String, default="")
    l1_started: Mapped[str] = mapped_column(String, default="")
    l2: Mapped[str] = mapped_column(String, default="")
    l3: Mapped[str] = mapped_column(String, default="")
    closed: Mapped[str] = mapped_column(String, default="")
    resolution_time: Mapped[str] = mapped_column(String, default="")
    sla_violated: Mapped[str] = mapped_column(String, default="")
    root_cause: Mapped[str] = mapped_column(String, default="")
    description: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[str] = mapped_column(String)
    updated_at: Mapped[str] = mapped_column(String)
