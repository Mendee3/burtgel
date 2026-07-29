from sqlalchemy.orm import Session as DbSession

from burtgel_api.auth.sessions import now_utc
from burtgel_api.db.models import AuditLog, User


def record_audit(
    db: DbSession,
    actor_user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: object = None,
    department_id: int | None = None,
    details: str = "",
    target_user_id: int | None = None,
) -> None:
    actor_name = None
    if actor_user_id:
        actor = db.get(User, actor_user_id)
        if actor:
            actor_name = actor.display_name or actor.email or actor.username
    db.add(
        AuditLog(
            actor_user_id=actor_user_id,
            actor_name=actor_name,
            target_user_id=target_user_id,
            department_id=department_id,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id or ""),
            details=details,
            created_at=now_utc().isoformat(),
        )
    )
