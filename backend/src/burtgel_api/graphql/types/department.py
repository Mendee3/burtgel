import strawberry


@strawberry.type
class DepartmentType:
    id: strawberry.ID
    code: str
    slug: str
    name: str
