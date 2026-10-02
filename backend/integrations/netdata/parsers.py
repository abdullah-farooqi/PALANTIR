import math
from typing import Any, Dict, List, Mapping, Optional, Sequence
from .schemas import NetdataDataResponse, NetdataWeightsResponse
from .normalizer import strip_machine_guid


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
        if not row:
            continue
        entry = {"timestamp": row[0]}
        for i, label in enumerate(labels[1:], start=1):
            clean_label = strip_machine_guid(label) if label != "timestamp" else "timestamp"
            entry[clean_label] = extract_value(row[i]) if i < len(row) else None
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
    if result is None:
        return rates
    if isinstance(result, dict):
        for context, data in result.items():
            if isinstance(data, dict):
                value = data.get("anomaly_rate")
                if value is None:
                    value = data.get("anomaly-rate", data.get("value"))
            else:
                value = data
            rate = _normalize_anomaly_rate(value)
            if rate is not None:
                rates[context] = rate
        return rates

    dictionaries = response.dictionaries or {}
    contexts = dictionaries.get("contexts", [])
    for item in result:
        context = None
        value = None

        if isinstance(item, dict):
            context = _resolve_context(
                item.get("context"), contexts
            )
            if context is None:
                context = _resolve_context(item.get("dimension"), contexts)
            if context is None:
                context = item.get("id")
            if context is None:
                context = _dictionary_item(contexts, item.get("ci"))
            value = item.get("anomaly_rate")
            if value is None:
                value = item.get("value")
        elif isinstance(item, list):
            # v3 weights uses schema columns: row_type, node, context,
            # instance, dimension, weight, timeframe[min..anomaly_count].
            if len(item) > 2:
                context = _resolve_context(item[2], contexts)
            if len(item) > 6 and isinstance(item[6], (list, tuple, dict)):
                timeframe = item[6]
                if isinstance(timeframe, dict):
                    count = timeframe.get("count")
                    anomaly_count = timeframe.get("anomaly_count")
                elif len(timeframe) > 5:
                    count = timeframe[4]
                    anomaly_count = timeframe[5]
                else:
                    count = anomaly_count = None
                if count is not None and anomaly_count is not None:
                    try:
                        count = float(count)
                        anomaly_count = float(anomaly_count)
                        value = anomaly_count / count if count else 0.0
                    except (TypeError, ValueError):
                        value = None

        rate = _normalize_anomaly_rate(value)
        if context is not None and rate is not None:
            rates[str(context)] = rate
    return rates


def _normalize_anomaly_rate(value) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (list, tuple)):
        if len(value) >= 6:
            try:
                count = float(value[4])
                anomaly_count = float(value[5])
                return max(0.0, min(1.0, anomaly_count / count if count else 0.0))
            except (TypeError, ValueError):
                return None
        if not value:
            return None
        value = value[0]
    try:
        rate = float(value)
    except (ValueError, TypeError):
        return None
    if math.isnan(rate) or math.isinf(rate):
        return None
    return max(0.0, min(1.0, rate))


def _dictionary_item(dictionary: Any, index: Any) -> Optional[Any]:
    if isinstance(index, bool):
        return None
    if isinstance(index, float) and not index.is_integer():
        return None
    try:
        numeric_index = int(index)
    except (TypeError, ValueError):
        return None
    if numeric_index < 0:
        return None
    if isinstance(dictionary, Mapping):
        return dictionary.get(numeric_index, dictionary.get(str(numeric_index)))
    if isinstance(dictionary, Sequence) and not isinstance(dictionary, (str, bytes)):
        if numeric_index < len(dictionary):
            return dictionary[numeric_index]
    return None


def _resolve_context(value: Any, dictionaries: Any) -> Optional[Any]:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _dictionary_item(dictionaries, value)
    return value
