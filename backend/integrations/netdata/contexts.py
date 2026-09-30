# Verified Netdata Context Constants
# [VERIFIED] Wrong names return HTTP 200 with 0 rows. No error.

class NetworkContexts:
    BANDWIDTH = "net.net"           # [VERIFIED] net.eth0 -> 0 rows silently
    PACKETS   = "net.packets"
    ERRORS    = "net.errors"
    DROPS     = "net.drops"


class SystemContexts:
    CPU   = "system.cpu"
    RAM   = "system.ram"
    SWAP  = "mem.swap"              # [VERIFIED] system.swap -> 0 rows silently
    LOAD  = "system.load"


class ProcessContexts:
    CPU     = "app.cpu_utilization" # [VERIFIED] apps.cpu -> 0 rows silently
    MEMORY  = "app.mem_usage"       # [VERIFIED] apps.mem -> 0 rows silently
    FILES   = "app.fds_open"        # [VERIFIED] apps.files -> 0 rows silently
    THREADS = "app.threads"


class ContainerContexts:
    CPU    = "cgroup.cpu"
    MEMORY = "cgroup.mem_usage"


# SocketContexts intentionally absent.
# network-connections Function: HTTP 412 on all local callers.
# Requires Netdata Cloud SSO. No config workaround.
# [SOURCE] network-viewer.c: SIGNED_ID|SAME_SPACE|SENSITIVE_DATA
# Per-process socket attribution -> PALANTIR PCAP pipeline.
