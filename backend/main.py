import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from api.v1.nodes import router as nodes_router
from api.v1.metrics import router as metrics_router
from api.v1.alerts import router as alerts_router
from api.v1.investigations import router as investigations_router
from api.v1.internal import router as internal_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="PALANTIR Backend API — Netdata Sensor & Autonomous Security Investigation Engine",
    version="1.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health endpoint
@app.get("/healthz", tags=["Health"])
async def healthz():
    return {"status": "ok", "app": settings.PROJECT_NAME}

# Internal router (Netdata webhook)
app.include_router(internal_router, prefix="/internal", tags=["Internal Webhooks"])

# Public API v1 routers
app.include_router(nodes_router, prefix=settings.API_V1_STR)
app.include_router(metrics_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(investigations_router, prefix=settings.API_V1_STR)
