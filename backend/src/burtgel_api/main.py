import importlib.util

from a2wsgi import WSGIMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from strawberry.fastapi import GraphQLRouter

from burtgel_api.config import BASE_DIR
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


def _load_legacy_wsgi_app():
    spec = importlib.util.spec_from_file_location("burtgel_legacy_app", BASE_DIR / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


frontend_dist = BASE_DIR / "frontend" / "dist"
if frontend_dist.is_dir():
    @app.get("/incidents")
    def incidents_redirect() -> RedirectResponse:
        return RedirectResponse(url="/incidents/")

    app.mount("/incidents", StaticFiles(directory=frontend_dist, html=True), name="incidents-spa")

app.mount("/", WSGIMiddleware(_load_legacy_wsgi_app()))
