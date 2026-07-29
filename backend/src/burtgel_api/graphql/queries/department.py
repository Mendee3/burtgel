import strawberry
from strawberry.types import Info

from burtgel_api.auth.permissions import departments_for_user
from burtgel_api.graphql.converters import to_department_type
from burtgel_api.graphql.require_login import require_login
from burtgel_api.graphql.types import DepartmentType


@strawberry.type
class DepartmentQuery:
    @strawberry.field
    def departments(self, info: Info) -> list[DepartmentType]:
        user = require_login(info)
        rows = departments_for_user(info.context.db, user)
        return [to_department_type(d) for d in rows]
