import os
import pytest
from pathlib import Path
from sqlalchemy import text
from core.database import sync_engine, AsyncSessionLocal
from models.node import MonitoredNode
from sqlalchemy import select


@pytest.fixture(scope="session", autouse=True)
def initialize_test_database():
    """
    Auto-initialize database schema from sql/init.sql if tables are not yet created.
    Guarantees clean execution on bare test runners (e.g. GitHub Actions CI).
    """
    possible_paths = [
        Path(__file__).resolve().parent.parent.parent / "sql" / "init.sql",
        Path("/app/sql/init.sql"),
        Path("sql/init.sql"),
        Path("../sql/init.sql"),
    ]
    init_sql_path = None
    for p in possible_paths:
        if p.exists():
            init_sql_path = p
            break

    if init_sql_path:
        try:
            with sync_engine.begin() as conn:
                res = conn.execute(text("SELECT to_regclass('public.monitored_nodes')")).scalar()
                if not res:
                    sql_text = init_sql_path.read_text()
                    for statement in sql_text.split(";"):
                        stmt = statement.strip()
                        if stmt:
                            conn.execute(text(stmt))
        except Exception as e:
            # If DB is not available (e.g. unit tests without DB), allow tests to proceed or fail gracefully
            pass

    migrations_dir = Path(__file__).resolve().parents[2] / "sql" / "migrations"
    for migration_name in (
        "20261116_pcap_manifest_contract.sql",
        "20261117_pcap_engine_enrichment.sql",
        "20261118_pcap_threat_intel_cache.sql",
    ):
        migration_path = migrations_dir / migration_name
        if not migration_path.exists():
            continue
        try:
            with sync_engine.begin() as conn:
                for statement in migration_path.read_text().split(";"):
                    statement = statement.strip()
                    if statement:
                        conn.execute(text(statement))
        except Exception:
            # Keep database-free unit tests runnable; DB-backed cases report the actual failure.
            pass

