from typing import Annotated, Union

import strawberry
from strawberry.types import Info

from burtgel_api.graphql.types.asset import ValidationError


@strawberry.type
class IncidentDeadlineType:
    deadline_at: str
    hours_allowed: int
    is_overdue: bool
    remaining_seconds: int


@strawberry.type
class IncidentCorrectiveActionType:
    id: strawberry.ID
    description: str
    added_by_name: str
    created_at: str


@strawberry.type
class IncidentSeverityChangeType:
    id: strawberry.ID
    previous_severity: str
    new_severity: str
    reason: str
    changed_by_name: str
    created_at: str


@strawberry.type
class IncidentAuditEntryType:
    id: strawberry.ID
    action: str
    actor_name: str | None
    details: str
    created_at: str


@strawberry.type
class IncidentType:
    id: strawberry.ID
    incident_id: str
    detected_date: str
    occurred_date: str
    reported_by: str
    system_location: str
    incident_type: str
    severity: str
    l1_started: str
    l2: str
    l3: str
    closed: str
    resolution_time: str
    sla_violated: str
    root_cause: str
    description: str
    created_at: str
    updated_at: str

    @strawberry.field
    def status(self, info: Info) -> str:
        from burtgel_api.db.models import IncidentCorrectiveAction
        from burtgel_api.services.incident_service import compute_incident_status

        has_action = (
            info.context.db.query(IncidentCorrectiveAction).filter_by(incident_id=int(self.id)).count() > 0
        )
        return compute_incident_status(self.severity, self.closed, self.created_at, has_action)

    @strawberry.field
    def deadline(self) -> IncidentDeadlineType:
        from burtgel_api.services.incident_service import compute_deadline

        d = compute_deadline(self.severity, self.created_at)
        return IncidentDeadlineType(
            deadline_at=d["deadline_at"],
            hours_allowed=d["hours_allowed"],
            is_overdue=d["is_overdue"],
            remaining_seconds=d["remaining_seconds"],
        )

    @strawberry.field
    def original_severity(self, info: Info) -> str:
        from burtgel_api.db.models import IncidentSeverityChange

        earliest = (
            info.context.db.query(IncidentSeverityChange)
            .filter_by(incident_id=int(self.id))
            .order_by(IncidentSeverityChange.id.asc())
            .first()
        )
        return earliest.previous_severity if earliest else self.severity

    @strawberry.field
    def corrective_actions(self, info: Info) -> list[IncidentCorrectiveActionType]:
        from burtgel_api.db.models import IncidentCorrectiveAction

        rows = (
            info.context.db.query(IncidentCorrectiveAction)
            .filter_by(incident_id=int(self.id))
            .order_by(IncidentCorrectiveAction.created_at.asc())
            .all()
        )
        return [
            IncidentCorrectiveActionType(
                id=strawberry.ID(str(r.id)), description=r.description, added_by_name=r.added_by_name,
                created_at=r.created_at,
            )
            for r in rows
        ]

    @strawberry.field
    def severity_history(self, info: Info) -> list[IncidentSeverityChangeType]:
        from burtgel_api.db.models import IncidentSeverityChange

        rows = (
            info.context.db.query(IncidentSeverityChange)
            .filter_by(incident_id=int(self.id))
            .order_by(IncidentSeverityChange.created_at.asc())
            .all()
        )
        return [
            IncidentSeverityChangeType(
                id=strawberry.ID(str(r.id)), previous_severity=r.previous_severity, new_severity=r.new_severity,
                reason=r.reason, changed_by_name=r.changed_by_name, created_at=r.created_at,
            )
            for r in rows
        ]

    @strawberry.field
    def audit_trail(self, info: Info) -> list[IncidentAuditEntryType]:
        from burtgel_api.db.models import AuditLog

        rows = (
            info.context.db.query(AuditLog)
            .filter_by(entity_type="attachment_incident", entity_id=str(self.id))
            .order_by(AuditLog.created_at.asc())
            .all()
        )
        return [
            IncidentAuditEntryType(
                id=strawberry.ID(str(r.id)), action=r.action, actor_name=r.actor_name, details=r.details,
                created_at=r.created_at,
            )
            for r in rows
        ]

    @strawberry.field
    def registered_by_name(self, info: Info) -> str | None:
        from burtgel_api.db.models import AuditLog

        row = (
            info.context.db.query(AuditLog)
            .filter_by(entity_type="attachment_incident", entity_id=str(self.id), action="create")
            .order_by(AuditLog.created_at.asc())
            .first()
        )
        return row.actor_name if row else None


@strawberry.type
class IncidentConnection:
    items: list[IncidentType]
    total_count: int


@strawberry.input
class IncidentInput:
    detected_date: str = ""
    occurred_date: str = ""
    reported_by: str = ""
    system_location: str = ""
    incident_type: str = ""
    severity: str = ""
    l1_started: str = ""
    l2: str = ""
    l3: str = ""
    closed: str = ""
    resolution_time: str = ""
    sla_violated: str = ""
    root_cause: str = ""
    description: str = ""


IncidentResult = Annotated[Union[IncidentType, ValidationError], strawberry.union("IncidentResult")]
