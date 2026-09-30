from typing import Optional, List, Dict
from .schemas import NetdataDataResponse, NetdataWeightsResponse


def extract_value(raw) -> Optional[float]:
    """
    [VERIFIED] json2 dimension values are [value, arp, pa] triples.
    Index 0 is the actual value. Never assume scalar.
    """
    if isinstance(raw, list) and len(raw) >= 1:
        v = raw[0]
        return float(v) if v is not None else None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def parse_rows(response: NetdataDataResponse) -> List[Dict]:
    """
    Normalize a Netdata v3 json2 response into flat dicts.
    Index 0 in every row is always the Unix timestamp.
    Context count differs per device — handles any shape dynamically.
    Everything above this function receives this shape, never raw Netdata JSON.
    """
    labels = response.result.labels
    rows = response.result.data
    parsed = []
    for row in rows:
        entry = {"timestamp": row[0]}
        for i, label in enumerate(labels[1:], start=1):
            entry[label] = extract_value(row[i]) if i < len(row) else None
        parsed.append(entry)
    return parsed


def parse_anomaly_rates(response: NetdataWeightsResponse) -> Dict[str, float]:
    """
    Extract anomaly rates per context.
    Returns empty dict during ML warmup (first 900s) — correct, not a bug.
    Caller must handle empty dict gracefully — never treat as error.
    """
    rates = {}
    result = response.result
    for context, data in result.items():
        if isinstance(data, dict) and "anomaly_rate" in data:
            rates[context] = float(data["anomaly_rate"])
    return rates
