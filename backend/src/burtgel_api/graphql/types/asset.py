from typing import Annotated, Union

import strawberry

from burtgel_api.graphql.types.department import DepartmentType


@strawberry.type
class AssetType:
    id: strawberry.ID
    department: DepartmentType
    asset_name: str
    description: str
    asset_type: str
    asset_group_code: str
    has_personal_data: str
    has_sensitive_data: str
    owner: str
    custodian: str
    location: str
    retention_period: str
    confidentiality: str
    integrity_impact: str
    availability_impact: str
    asset_value: str
    asset_category: str
    review_frequency: str
    created_at: str
    updated_at: str


@strawberry.type
class AssetConnection:
    items: list[AssetType]
    total_count: int


@strawberry.type
class AssetPermissions:
    can_read: bool
    can_update: bool
    editable_fields: list[str]


@strawberry.input
class AssetInput:
    asset_name: str = ""
    description: str = ""
    asset_type: str = ""
    asset_group_code: str = ""
    has_personal_data: str = ""
    has_sensitive_data: str = ""
    owner: str = ""
    custodian: str = ""
    location: str = ""
    retention_period: str = ""
    confidentiality: str = ""
    integrity_impact: str = ""
    availability_impact: str = ""
    review_frequency: str = ""


@strawberry.type
class ValidationError:
    message: str


AssetResult = Annotated[Union[AssetType, ValidationError], strawberry.union("AssetResult")]
