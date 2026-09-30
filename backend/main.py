import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.database import AsyncSessionLocal
from services.nodes import NodeService
from api.v1.nodes import router as nodes_router
from api.v1.metrics import router as metrics_router
from api.v1.alerts import router as alerts_router
from api.v1.investigations import router as investigations_router
from api.v1.internal import router as internal_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("palantir")


async def auto_register_local_node():
    """
    Zero-touch auto-registration:
    Polls local Netdata sensor on startup and registers/updates it in PostgreSQL.
    Runs asynchronously in the background so FastAPI starts immediately.
    """
    netdata_url = "http://netdata:19999"
    max_retries = 30
    delay = 2

    for attempt in range(1, max_retries + 1):
        try:
            async with AsyncSessionLocal() as session:
                node = await NodeService.register_node(
                    hostname="local-node",
                    netdata_url=netdata_url,
                    os_type="linux",
                    session=session,
                )
                logger.info(
                    f"✓ [ZERO-TOUCH] Auto-registered local Netdata sensor '{node.hostname}' "
                    f"(ID: {node.id}, Contexts: {node.context_count}, Alerts: {node.alert_count})"
                )
                return
        except Exception as exc:
            logger.debug(f"Waiting for Netdata sensor ({attempt}/{max_retries}): {exc}")
            await asyncio.sleep(delay)

    logger.warning(
        "Could not auto-register local Netdata node within timeout. "
        "It will be probed during periodic scheduled tasks."
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Trigger background auto-registration task on startup
    asyncio.create_task(auto_register_local_node())
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="PALANTIR Backend API — Netdata Sensor & Autonomous Security Investigation Engine",
    version="1.0.0",
    lifespan=lifespan,
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
