from fastapi import FastAPI
from .routes import direct, router_level, route_level, annotated, nested, public

app = FastAPI()
app.include_router(direct.router)
app.include_router(router_level.router)
app.include_router(route_level.router)
app.include_router(annotated.router)
app.include_router(nested.router)
app.include_router(public.router)
