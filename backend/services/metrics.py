import logging
from typing import List, Dict
from integrations.netdata.client import NetdataClient
from integrations.netdata.parsers import parse_rows
from integrations.netdata.contexts import (
    NetworkContexts,
    SystemContexts,
    ProcessContexts,
    ContainerContexts,
)
from integrations.netdata.exceptions import NetdataUnavailable
from models.metric import MetricSnapshot

logger = logging.getLogger(__name__)


class MetricsService:
    """
    Pull flow — business logic for metric collection.
    Nothing above this class knows Netdata exists.
    """

    def __init__(self, node_url: str):
        self.client = NetdataClient(base_url=node_url)

    async def collect_network(self) -> List[Dict]:
        raw = await self.client.get_metrics(
            contexts=[
                NetworkContexts.BANDWIDTH,
                NetworkContexts.PACKETS,
                NetworkContexts.ERRORS,
                NetworkContexts.DROPS,
            ],
            after=-60,
            group_by="instance",
        )
        return parse_rows(raw)

    async def collect_system(self) -> List[Dict]:
        raw = await self.client.get_metrics(
            contexts=[
                SystemContexts.CPU,
                SystemContexts.RAM,
                SystemContexts.SWAP,
                SystemContexts.LOAD,
            ],
            after=-60,
            group_by="instance",
        )
        return parse_rows(raw)

    async def collect_processes(self) -> List[Dict]:
        raw = await self.client.get_metrics(
            contexts=[
                ProcessContexts.CPU,
                ProcessContexts.MEMORY,
                ProcessContexts.FILES,
            ],
            after=-60,
            group_by="instance",
        )
        return parse_rows(raw)

    async def collect_containers(self) -> List[Dict]:
        raw = await self.client.get_metrics(
            contexts=[
                ContainerContexts.CPU,
                ContainerContexts.MEMORY,
            ],
            after=-60,
            group_by="instance",
        )
        return parse_rows(raw)

    async def collect_and_persist(self, node_id: int, session):
        """
        Called by Celery beat every 60 seconds.
        Collects all categories, writes to metric_snapshots.
        If one category fails (node offline or partial error) — logs and continues.
        Does not fail the whole task for one category.
        """
        categories = {
            "network": self.collect_network,
            "system": self.collect_system,
            "processes": self.collect_processes,
            "containers": self.collect_containers,
        }
        for category, collector in categories.items():
            try:
                rows = await collector()
                for row in rows:
                    session.add(
                        MetricSnapshot(
                            node_id=node_id,
                            category=category,
                            data=row,
                        )
                    )
            except NetdataUnavailable as e:
                logger.warning(
                    f"Node {node_id} offline/unavailable during {category} collection: {e}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error collecting {category} for node {node_id}: {e}"
                )
        session.commit()
