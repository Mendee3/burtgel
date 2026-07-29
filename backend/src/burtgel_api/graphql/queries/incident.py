import strawberry
from strawberry.types import Info

from burtgel_api.db.models import Incident
from burtgel_api.graphql.converters import to_incident_type
from burtgel_api.graphql.require_login import require_login
from burtgel_api.graphql.types import IncidentConnection


@strawberry.type
class IncidentQuery:
    @strawberry.field
    def incidents(self, info: Info, search: str | None = None) -> IncidentConnection:
        require_login(info)
        db = info.context.db
        query = db.query(Incident)
        if search:
            like = f"%{search}%"
            query = query.filter(Incident.incident_id.ilike(like) | Incident.system_location.ilike(like))
        rows = query.order_by(Incident.created_at.desc()).all()
        return IncidentConnection(items=[to_incident_type(i) for i in rows], total_count=len(rows))
