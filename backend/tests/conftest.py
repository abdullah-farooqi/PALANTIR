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

