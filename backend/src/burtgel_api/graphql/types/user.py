import strawberry

from burtgel_api.graphql.types.department import DepartmentType


@strawberry.type
class UserType:
    id: strawberry.ID
    username: str
    email: str | None
    display_name: str
    role: str
    must_change_password: bool
    department: DepartmentType | None


@strawberry.type
class LoginResult:
    success: bool
    message: str
    user: UserType | None = None
    csrf_token: str = ""


@strawberry.type
class MutationResult:
    success: bool
    message: str
