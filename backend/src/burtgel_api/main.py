from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from strawberry.fastapi import GraphQLRouter

from burtgel_api.db.base import Base
from burtgel_api.db.session import engine
from burtgel_api.graphql.context import get_context
from burtgel_api.graphql.schema import schema

app = FastAPI(title="burtgel-api")


@app.on_event("startup")
def create_new_tables() -> None:
    Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

graphql_app = GraphQLRouter(schema, context_getter=get_context)
app.include_router(graphql_app, prefix="/graphql")


@app.get("/healthz")
def healthz() -> dict[str, bool]:
    return {"ok": True}
