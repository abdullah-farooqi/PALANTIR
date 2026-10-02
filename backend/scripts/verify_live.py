#!/usr/bin/env python3
"""Verify PALANTIR's Netdata integration against a live host agent."""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from integrations.netdata.client import NetdataClient
from integrations.netdata.contexts import NetworkContexts, ProcessContexts, SystemContexts
from integrations.netdata.parsers import parse_anomaly_rates, parse_rows


BASE_URL = os.environ.get("NETDATA_URL", "http://localhost:19999")
failures = []


def check(label: str, condition: bool, detail: str) -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}: {detail}")
    if not condition:
        failures.append(label)


def context_names(contexts) -> list[str]:
    if isinstance(contexts, list):
        return [str(item) for item in contexts]
    if isinstance(contexts, dict):
        values = contexts.get("contexts", contexts)
        if isinstance(values, dict):
            return [str(item) for item in values]
        if isinstance(values, list):
            return [str(item) for item in values]
    return []


def json2_shape(response) -> tuple[bool, str]:
    labels = response.result.labels
    rows = response.result.data
    if not labels or not rows:
        return False, f"labels={len(labels)}, rows={len(rows)}"
    if any(not isinstance(row, list) or len(row) != len(labels) for row in rows):
        return False, f"labels={len(labels)}, rows={len(rows)}"
    values = [value for row in rows for value in row[1:]]
    triples = sum(isinstance(value, list) and len(value) >= 3 for value in values)
    return triples > 0, f"labels={len(labels)}, rows={len(rows)}, triples={triples}"


async def main() -> int:
    failures.clear()
    client = NetdataClient(BASE_URL, timeout=10.0)
    print(f"Verifying Netdata host endpoints at {BASE_URL}\n")

    try:
        v1_info = await client.info()
        v3_info = await client.info_v3()
        metadata = await client.get_host_metadata()
        check("v1 info", bool(v1_info.version), v1_info.version)
        check(
            "v3 agent identity",
            bool(v3_info.agents) and bool(metadata["machine_guid"]),
            str(metadata["machine_guid"]),
        )
        check(
            "host labels",
            bool(v1_info.host_labels) and bool(metadata["hostname"]),
            str(metadata["hostname"]),
        )
        check("host RAM", metadata["ram_total"] not in (None, ""), str(metadata["ram_total"]))

        contexts = await client.get_contexts()
        names = context_names(contexts)
        check("contexts discovered", bool(names), str(len(names)))

        network_response = await client.get_metrics(
            [NetworkContexts.BANDWIDTH], after=-60, group_by="instance"
        )
        network_shape, network_detail = json2_shape(network_response)
        check("network JSON2 shape", network_shape, network_detail)
        network = parse_rows(network_response)
        check("network rows", bool(network), str(len(network)))

        system_response = await client.get_metrics(
            [SystemContexts.CPU, SystemContexts.RAM], after=-60, group_by=None
        )
        system_shape, system_detail = json2_shape(system_response)
        check("system JSON2 shape", system_shape, system_detail)
        system = parse_rows(system_response)
        check("system rows", bool(system), str(len(system)))

        bogus = await client.get_metrics(
            ["palantir.invalid_context"], after=-60, group_by="instance"
        )
        check("unknown context is detected", not bogus.result.data, str(len(bogus.result.data)))

        processes = parse_rows(
            await client.get_metrics([ProcessContexts.CPU], after=-60, group_by="instance")
        )
        app_contexts = [name for name in names if name.startswith("app.")]
        check("process contexts", bool(app_contexts), str(len(app_contexts)))
        check("process rows", bool(processes), str(len(processes)))

        weights = await client.get_anomaly_scores([SystemContexts.CPU], after=-300)
        check(
            "anomaly method",
            weights.request.get("method") == "anomaly-rate",
            str(weights.request.get("method")),
        )
        print(f"  [INFO] anomaly entries: {len(parse_anomaly_rates(weights))}")

        current_alerts = await client.get_current_alerts()
        alert_envelope = all(key in current_alerts for key in ("api", "nodes", "timings"))
        check("current-alert envelope", alert_envelope, str(sorted(current_alerts)))
        print("  [INFO] an empty current-alert set is healthy, not a failed health subsystem")
    except Exception as exc:
        check("host endpoint requests", False, f"{type(exc).__name__}: {exc}")

    if failures:
        print(f"\nFAILED: {', '.join(failures)}")
        return 1
    print("\nAll host endpoint checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
