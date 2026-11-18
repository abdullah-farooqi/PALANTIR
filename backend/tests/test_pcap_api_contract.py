from api.v1.investigations import _safe_evidence_error, _safe_evidence_filename


def test_evidence_api_hides_host_paths_and_agent_credentials():
    message = _safe_evidence_error(
        "Transfer failed at /var/lib/host/capture.pcap from http://user:secret@agent.local; "
        "Authorization: Bearer session-secret token=query-secret C:\\host\\capture.pcap"
    )

    assert message == (
        "Transfer failed at [path] from http://[redacted]@agent.local; "
        "Authorization: [redacted] token=[redacted] [path]"
    )
    assert "secret" not in message
    assert "/var/lib" not in message
    assert "C:\\host" not in message


def test_evidence_filename_is_a_basename_for_legacy_rows():
    assert _safe_evidence_filename("/var/lib/host/capture.pcap") == "capture.pcap"
    assert _safe_evidence_filename(r"C:\\host\\capture.pcap") == "capture.pcap"
    assert _safe_evidence_filename("../") is None
