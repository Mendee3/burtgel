import strawberry

from burtgel_api.graphql.mutations.asset import AssetMutation
from burtgel_api.graphql.mutations.auth import AuthMutation
from burtgel_api.graphql.mutations.incident import IncidentMutation
from burtgel_api.graphql.queries.asset import AssetQuery
from burtgel_api.graphql.queries.auth import AuthQuery
from burtgel_api.graphql.queries.department import DepartmentQuery
from burtgel_api.graphql.queries.incident import IncidentQuery


@strawberry.type
class Query(AssetQuery, DepartmentQuery, AuthQuery, IncidentQuery):
    pass


@strawberry.type
class Mutation(AssetMutation, AuthMutation, IncidentMutation):
    pass


schema = strawberry.Schema(query=Query, mutation=Mutation)
