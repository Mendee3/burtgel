import strawberry

from burtgel_api.db.models import Asset, Incident, User
from burtgel_api.graphql.types import AssetType, DepartmentType, IncidentType, UserType


def to_department_type(dept) -> DepartmentType:
    return DepartmentType(id=strawberry.ID(str(dept.id)), code=dept.code, slug=dept.slug, name=dept.name)


def to_user_type(user: User) -> UserType:
    dept = user.department
    return UserType(
        id=strawberry.ID(str(user.id)),
        username=user.username,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        must_change_password=bool(user.must_change_password),
        department=to_department_type(dept) if dept else None,
    )


def to_asset_type(asset: Asset) -> AssetType:
    return AssetType(
        id=strawberry.ID(str(asset.id)),
        department=to_department_type(asset.department),
        asset_name=asset.asset_name,
        description=asset.description,
        asset_type=asset.asset_type,
        asset_group_code=asset.asset_group_code,
        has_personal_data=asset.has_personal_data,
        has_sensitive_data=asset.has_sensitive_data,
        owner=asset.owner,
        custodian=asset.custodian,
        location=asset.location,
        retention_period=asset.retention_period,
        confidentiality=asset.confidentiality,
        integrity_impact=asset.integrity_impact,
        availability_impact=asset.availability_impact,
        asset_value=asset.asset_value,
        asset_category=asset.asset_category,
        review_frequency=asset.review_frequency,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


def to_incident_type(incident: Incident) -> IncidentType:
    return IncidentType(
        id=strawberry.ID(str(incident.id)),
        incident_id=incident.incident_id,
        detected_date=incident.detected_date,
        occurred_date=incident.occurred_date,
        reported_by=incident.reported_by,
        system_location=incident.system_location,
        incident_type=incident.incident_type,
        severity=incident.severity,
        l1_started=incident.l1_started,
        l2=incident.l2,
        l3=incident.l3,
        closed=incident.closed,
        resolution_time=incident.resolution_time,
        sla_violated=incident.sla_violated,
        root_cause=incident.root_cause,
        description=incident.description,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )
