"""Incident Register access, driven by the VulnReg roles stored in users.vuln_role.

- System Superadmin: full access.
- InfoSec: full access (create, edit, delete, corrective actions, severity changes).
- IT Head, CTO: read-only.
- Everyone else (incl. system Admins without one of these roles, and Engineers): no access.

Roles held as an active substitute (vuln_substitutes, same rule as VulnReg) count too.
Keep in sync with incident_access() in app.py, which drives the nav menu.
"""

from sqlalchemy import text
from sqlalchemy.orm import Session as DbSession

from burtgel_api.auth.permissions import is_superadmin
from burtgel_api.auth.sessions import now_utc
from burtgel_api.db.models import User

INCIDENT_MANAGE_ROLES = {"infosec"}
INCIDENT_VIEW_ROLES = {"infosec", "it_head", "cto"}


def effective_vuln_roles(db: DbSession, user: User) -> set[str]:
    roles = {r.strip() for r in (user.vuln_role or "").split(",") if r.strip()}
    today = now_utc().date().isoformat()
    try:
        rows = db.execute(
            text(
                "SELECT role FROM vuln_substitutes WHERE substitute_id = :uid AND revoked_at = '' "
                "AND start_date <= :today AND end_date >= :today"
            ),
            {"uid": user.id, "today": today},
        ).all()
        roles |= {r[0] for r in rows}
    except Exception:  # table not created yet
        pass
    return roles


def incident_access(db: DbSession, user: User | None) -> tuple[bool, bool]:
    """(can_view, can_manage) for the Incident Register."""
    if not user:
        return False, False
    if is_superadmin(user):
        return True, True
    roles = effective_vuln_roles(db, user)
    can_manage = bool(roles & INCIDENT_MANAGE_ROLES)
    return can_manage or bool(roles & INCIDENT_VIEW_ROLES), can_manage
