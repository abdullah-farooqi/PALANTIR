import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.api_auth import require_read
from core.database import AsyncSessionLocal
from services.nodes import NodeService
from api.v1.nodes import router as nodes_router
from api.v1.metrics import router as metrics_router
from api.v1.alerts import router as alerts_router
from api.v1.investigations import router as investigations_router
from api.v1.internal import router as internal_router
from api.v1.logs import router as logs_router
from api.v1.fleet import router as fleet_router
from api.v1.events import router as events_router
from api.v1.catalog import router as metric_catalog_router
from api.v1.fleet_logs import router as fleet_logs_router
from api.v1.health import router as operational_health_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("palantir")


async def auto_register_local_node():
    """
    Optional zero-touch registration of a host collector next to the central stack.
    Only runs when LOCAL_COLLECTOR_URL is set (e.g. http://host.docker.internal:20000).
    """
    collector_url = settings.LOCAL_COLLECTOR_URL.strip()
    if not collector_url:
        return
    for attempt in range(1, 31):
        try:
            async with AsyncSessionLocal() as session:
                node = await NodeService.register_node(
                    hostname=settings.LOCAL_NODE_HOSTNAME,
                    collector_url=collector_url,
                    os_type="linux",
                    session=session,
                )
                logger.info(f"Auto-registered local host collector '{node.hostname}' (ID: {node.id})")
                return
        except Exception as exc:
            logger.debug(f"Waiting for local host collector ({attempt}/30): {exc}")
            await asyncio.sleep(2)
    logger.warning("Could not auto-register the local host collector within the timeout.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Trigger background auto-registration task on startup
    asyncio.create_task(auto_register_local_node())
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="PALANTIR Backend API — Host Collector & Autonomous Security Investigation Engine",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Health endpoint
@app.get("/healthz", tags=["Health"])
async def healthz():
    return {"status": "ok", "app": settings.PROJECT_NAME}

# Internal router (alert webhook)
app.include_router(internal_router, prefix="/internal", tags=["Internal Webhooks"])

# Public API v1 routers
app.include_router(nodes_router, prefix=settings.API_V1_STR)
app.include_router(metrics_router, prefix=settings.API_V1_STR, dependencies=[Depends(require_read)])
app.include_router(logs_router, prefix=settings.API_V1_STR, dependencies=[Depends(require_read)])
app.include_router(alerts_router, prefix=settings.API_V1_STR, dependencies=[Depends(require_read)])
app.include_router(fleet_router, prefix=settings.API_V1_STR, dependencies=[Depends(require_read)])
app.include_router(events_router, prefix=settings.API_V1_STR, dependencies=[Depends(require_read)])
app.include_router(fleet_logs_router, prefix=settings.API_V1_STR, dependencies=[Depends(require_read)])
app.include_router(operational_health_router, prefix=settings.API_V1_STR, dependencies=[Depends(require_read)])
app.include_router(metric_catalog_router, prefix=settings.API_V1_STR)
app.include_router(
    investigations_router,
    prefix=settings.API_V1_STR,
    dependencies=[Depends(require_read)],
)
