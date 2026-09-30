class NetdataUnavailable(Exception):
    """Agent unreachable, non-200 response, or timeout."""
    pass


class NetdataParseError(Exception):
    """Response shape was unexpected."""
    pass
