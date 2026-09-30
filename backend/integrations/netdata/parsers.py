import math
from typing import Optional, List, Dict
from .schemas import NetdataDataResponse, NetdataWeightsResponse


def extract_value(raw) -> Optional[float]:
    """
    [VERIFIED] json2 dimension values are [value, arp, pa] triples.
    Index 0 is the actual value. Never assume scalar.
    Guards against NaN, Inf, and non-numeric types.
    """
    if isinstance(raw, list) and len(raw) >= 1:
        v = raw[0]
        if v is None:
            return None
        try:
            val = float(v)
            if math.isnan(val) or math.isinf(val):
                return None
            return val
        except (TypeError, ValueError):
            return None
    try:
        val = float(raw)
        if math.isnan(val) or math.isinf(val):
            return None
        return val
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
    if isinstance(result, dict):
        for context, data in result.items():
            if isinstance(data, dict) and "anomaly_rate" in data:
                try:
                    ar = float(data["anomaly_rate"])
                    if not math.isnan(ar) and not math.isinf(ar):
                        rates[context] = max(0.0, min(1.0, ar))
                except (ValueError, TypeError):
                    continue
    return rates

