import strawberry
from strawberry.types import Info

from burtgel_api.auth.sessions import now_utc
from burtgel_api.db.models import Incident, IncidentCorrectiveAction, IncidentSeverityChange
from burtgel_api.graphql.converters import to_incident_type
from burtgel_api.graphql.require_login import require_login
from burtgel_api.graphql.types import MutationResult
from burtgel_api.graphql.types.incident import IncidentInput, IncidentResult
from burtgel_api.graphql.types.asset import ValidationError
from burtgel_api.services.incident_service import (
    STATUS_CLOSED,
    SEVERITY_OPTIONS,
    compute_incident_status,
    generate_incident_id,
    normalize_text,
    validate_incident_form,
)
from burtgel_api.services.audit_service import record_audit


def _require_csrf(info: Info) -> None:
    if not info.context.csrf_ok():
        raise Exception("Хүсэлт хүчингүй байна. Дахин ачаална уу.")


def _actor_name(user) -> str:
    return user.display_name or user.email or user.username


@strawberry.type
class IncidentMutation:
    @strawberry.mutation
    def create_incident(self, info: Info, input: IncidentInput) -> IncidentResult:
        user = require_login(info)
        _require_csrf(info)
        db = info.context.db

        form = strawberry.asdict(input)
        values, error = validate_incident_form(form)
        if error:
            return ValidationError(message=error)

        timestamp = now_utc().isoformat()
        incident = Incident(incident_id=generate_incident_id(db), created_at=timestamp, updated_at=timestamp, **values)
        db.add(incident)
        db.flush()
        record_audit(
            db, user.id, "create", "attachment_incident", entity_id=incident.id,
            details=f"{incident.incident_id} зөрчил бүртгэгдлээ.",
        )
        db.commit()
        return to_incident_type(incident)

    @strawberry.mutation
    def update_incident(self, info: Info, id: strawberry.ID, input: IncidentInput) -> IncidentResult:
        user = require_login(info)
        _require_csrf(info)
        db = info.context.db

        incident = db.get(Incident, int(id))
        if incident is None:
            return ValidationError(message="Зөрчил олдсонгүй.")

        form = strawberry.asdict(input)
        values, error = validate_incident_form(form)
        if error:
            return ValidationError(message=error)

        for field, value in values.items():
            setattr(incident, field, value)
        incident.updated_at = now_utc().isoformat()
        record_audit(
            db, user.id, "update", "attachment_incident", entity_id=incident.id,
            details=f"{incident.incident_id} зөрчил шинэчлэгдлээ.",
        )
        db.commit()
        return to_incident_type(incident)

    @strawberry.mutation
    def delete_incident(self, info: Info, id: strawberry.ID) -> MutationResult:
        user = require_login(info)
        _require_csrf(info)
        db = info.context.db

        incident = db.get(Incident, int(id))
        if incident is None:
            return MutationResult(success=False, message="Зөрчил олдсонгүй.")

        incident_id = incident.incident_id
        db.delete(incident)
        record_audit(db, user.id, "delete", "attachment_incident", entity_id=id, details=f"{incident_id} зөрчил устгагдлаа.")
        db.commit()
        return MutationResult(success=True, message="Зөрчил устгагдлаа.")

    @strawberry.mutation
    def add_corrective_action(self, info: Info, incident_id: strawberry.ID, description: str) -> IncidentResult:
        user = require_login(info)
        _require_csrf(info)
        db = info.context.db

        incident = db.get(Incident, int(incident_id))
        if incident is None:
            return ValidationError(message="Зөрчил олдсонгүй.")

        description = normalize_text(description)
        if not description:
            return ValidationError(message="Хариу арга хэмжээний тайлбарыг бөглөнө үү.")

        has_action = (
            db.query(IncidentCorrectiveAction).filter_by(incident_id=incident.id).count() > 0
        )
        current_status = compute_incident_status(incident.severity, incident.closed, incident.created_at, has_action)
        if current_status == STATUS_CLOSED:
            return ValidationError(message="Зөрчил хаагдсан тул хариу арга хэмжээ нэмэх боломжгүй.")

        timestamp = now_utc().isoformat()
        db.add(
            IncidentCorrectiveAction(
                incident_id=incident.id, description=description, added_by_user_id=user.id,
                added_by_name=_actor_name(user), created_at=timestamp,
            )
        )
        record_audit(
            db, user.id, "corrective_action", "attachment_incident", entity_id=incident.id,
            details=f"{incident.incident_id}: хариу арга хэмжээ нэмэгдлээ.",
        )
        db.commit()
        return to_incident_type(incident)

    @strawberry.mutation
    def change_incident_severity(
        self, info: Info, incident_id: strawberry.ID, new_severity: str, reason: str
    ) -> IncidentResult:
        user = require_login(info)
        _require_csrf(info)
        db = info.context.db

        incident = db.get(Incident, int(incident_id))
        if incident is None:
            return ValidationError(message="Зөрчил олдсонгүй.")

        new_severity = normalize_text(new_severity)
        reason = normalize_text(reason)
        if new_severity not in SEVERITY_OPTIONS:
            return ValidationError(message="Severity талбарын утга буруу байна.")
        if not reason:
            return ValidationError(message="Ноцлолын зэрэг өөрчлөх шалтгааныг бөглөнө үү.")
        if new_severity == incident.severity:
            return ValidationError(message="Шинэ ноцлолын зэрэг одоогийнхтой ижил байна.")

        timestamp = now_utc().isoformat()
        previous_severity = incident.severity
        db.add(
            IncidentSeverityChange(
                incident_id=incident.id, previous_severity=previous_severity, new_severity=new_severity,
                reason=reason, changed_by_user_id=user.id, changed_by_name=_actor_name(user), created_at=timestamp,
            )
        )
        incident.severity = new_severity
        incident.updated_at = timestamp
        record_audit(
            db, user.id, "severity_change", "attachment_incident", entity_id=incident.id,
            details=f"{incident.incident_id}: ноцлолын зэрэг {previous_severity} -> {new_severity} ({reason})",
        )
        db.commit()
        return to_incident_type(incident)
