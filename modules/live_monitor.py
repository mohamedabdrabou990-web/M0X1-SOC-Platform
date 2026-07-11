
import os
import argparse
import logging
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    # Real, shared Alert Manager module — this is the actual integration
    # point with the rest of the M0X1 SOC Platform: modules/alert_manager.py.
    from modules.alert_manager import create_alert
except ImportError:
    try:
        # Fallback for running this file directly from inside modules/
        # (matches how this script is invoked per the usage docstring above:
        # `sudo python3 network_monitor.py`, which may not have the package
        # root on sys.path).
        from alert_manager import create_alert
    except ImportError:  # pragma: no cover - standalone fallback only
        def create_alert(source_module: str, alert_type: str, description: str, severity: str = "MEDIUM"):
            """
            Minimal fallback used only if modules/alert_manager.py truly
            cannot be found. Keeps this monitor usable in isolation without
            losing alert data — writes to logs/alerts.log instead of
            reports/alerts.json until the real Alert Manager is importable.
            """
            import json as _json
            fallback_path = os.path.join("logs", "alerts.log")
            os.makedirs(os.path.dirname(fallback_path) or ".", exist_ok=True)
            entry = {
                "timestamp": datetime.now().isoformat(),
                "source_module": source_module,
                "alert_type": alert_type,
                "description": description,
                "severity": severity,
            }
            with open(fallback_path, "a", encoding="utf-8") as f:
                f.write(_json.dumps(entry) + "\n")
            return entry

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    raise SystemExit(
        "scapy is required. Install it with:\n    pip install scapy"
    )

# =========================================================================
# CONFIGURATION — tune these to your environment
# =========================================================================

CONFIG = {
    # Network interface to listen on. Set to None to let scapy pick default.
    # Examples: "eth0", "wlan0", "en0"
    "interface": None,

    # Rolling time window (seconds) used to evaluate thresholds below.
    "time_window": 10,

    # PORT SCAN DETECTION
    # Alert if a single source IP contacts >= this many DISTINCT ports
    # within time_window seconds.
    "port_scan_threshold": 15,

    # FLOOD / DDoS DETECTION
    # Alert if a single source IP sends >= this many packets
    # (total) within time_window seconds.
    "flood_packet_threshold": 300,

    # Alert if a single source IP sends >= this many SYN packets
    # (connection attempts) within time_window seconds — classic SYN flood.
    "syn_flood_threshold": 100,

    # Seconds to wait before the same source IP can trigger the same
    # alert type again (prevents log spam).
    "alert_cooldown": 30,

    # Log file path (also settable via --log)
    "log_file": os.path.join("logs", "network_monitor.log"),
}

# =========================================================================
# INTERNAL STATE
# =========================================================================

# source_ip -> deque of (timestamp, dest_port)
port_activity = defaultdict(deque)

# source_ip -> deque of timestamps (all packets)
packet_activity = defaultdict(deque)

# source_ip -> deque of timestamps (SYN packets only)
syn_activity = defaultdict(deque)

# (source_ip, alert_type) -> last alert time, for cooldown
last_alert_time = {}


def setup_logging(log_file: str) -> logging.Logger:
    # إنشاء فولدر logs لو مش موجود
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger("network_monitor")
    logger.setLevel(logging.INFO)

    # منع تكرار الـ Handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def _raise_monitor_alert(alert_type: str, description: str, severity: str, logger: logging.Logger) -> None:
    """
    Forward a detection to the shared Alert Manager (reports/alerts.json).

    Wrapped defensively so that any problem raising the alert (disk full,
    corrupted alerts.json, etc.) is logged but never interrupts live packet
    sniffing — the monitor's primary job.
    """
    try:
        create_alert(
            source_module="Live Network Monitor",
            alert_type=alert_type,
            description=description,
            severity=severity,
        )
    except Exception as alert_error:  # noqa: BLE001 - alerting must never crash the sniffer
        logger.error(f"Failed to raise alert with Alert Manager: {alert_error}")


def _prune_old(dq: deque, now: float, window: int):
    """Remove entries older than `window` seconds from the left of dq."""
    while dq and now - dq[0][0] > window if isinstance(dq[0], tuple) else (dq and now - dq[0] > window):
        dq.popleft()


def _cooldown_ok(src_ip: str, alert_type: str, now: float, cooldown: int) -> bool:
    key = (src_ip, alert_type)
    last = last_alert_time.get(key, 0)
    if now - last >= cooldown:
        last_alert_time[key] = now
        return True
    return False


def analyze_packet(pkt, logger: logging.Logger, cfg: dict):
    if IP not in pkt:
        return

    src_ip = pkt[IP].src
    now = time.time()
    window = cfg["time_window"]

    # ---- Track all packets from this source (flood detection) ----
    packet_activity[src_ip].append(now)
    while packet_activity[src_ip] and now - packet_activity[src_ip][0] > window:
        packet_activity[src_ip].popleft()

    if len(packet_activity[src_ip]) >= cfg["flood_packet_threshold"]:
        if _cooldown_ok(src_ip, "flood", now, cfg["alert_cooldown"]):
            packet_count = len(packet_activity[src_ip])
            logger.warning(
                f"POSSIBLE DDoS/FLOOD from {src_ip}: "
                f"{packet_count} packets in last {window}s "
                f"(threshold: {cfg['flood_packet_threshold']})"
            )
            _raise_monitor_alert(
                alert_type="DDoS/Flood Detected",
                description=(
                    f"Source {src_ip} sent {packet_count} packets in the last "
                    f"{window}s (threshold: {cfg['flood_packet_threshold']})."
                ),
                severity="CRITICAL",
                logger=logger,
            )

    # ---- Track SYN packets specifically (SYN flood detection) ----
    if TCP in pkt and pkt[TCP].flags & 0x02:  # SYN flag set
        syn_activity[src_ip].append(now)
        while syn_activity[src_ip] and now - syn_activity[src_ip][0] > window:
            syn_activity[src_ip].popleft()

        if len(syn_activity[src_ip]) >= cfg["syn_flood_threshold"]:
            if _cooldown_ok(src_ip, "syn_flood", now, cfg["alert_cooldown"]):
                syn_count = len(syn_activity[src_ip])
                logger.warning(
                    f"POSSIBLE SYN FLOOD from {src_ip}: "
                    f"{syn_count} SYN packets in last {window}s "
                    f"(threshold: {cfg['syn_flood_threshold']})"
                )
                _raise_monitor_alert(
                    alert_type="SYN Flood Detected",
                    description=(
                        f"Source {src_ip} sent {syn_count} SYN packets in the last "
                        f"{window}s (threshold: {cfg['syn_flood_threshold']})."
                    ),
                    severity="CRITICAL",
                    logger=logger,
                )
      

    # ---- Track distinct destination ports (port scan detection) ----
    dest_port = None
    if TCP in pkt:
        dest_port = pkt[TCP].dport
    elif UDP in pkt:
        dest_port = pkt[UDP].dport

    if dest_port is not None:
        port_activity[src_ip].append((now, dest_port))
        while port_activity[src_ip] and now - port_activity[src_ip][0][0] > window:
            port_activity[src_ip].popleft()

        distinct_ports = {p for _, p in port_activity[src_ip]}
        if len(distinct_ports) >= cfg["port_scan_threshold"]:
            if _cooldown_ok(src_ip, "port_scan", now, cfg["alert_cooldown"]):
                logger.warning(
                    f"POSSIBLE PORT SCAN from {src_ip}: "
                    f"{len(distinct_ports)} distinct ports in last {window}s "
                    f"(threshold: {cfg['port_scan_threshold']})"
                )
                _raise_monitor_alert(
                    alert_type="Port Scan Detected",
                    description=(
                        f"Source {src_ip} contacted {len(distinct_ports)} distinct ports "
                        f"in the last {window}s (threshold: {cfg['port_scan_threshold']})."
                    ),
                    severity="HIGH",
                    logger=logger,
                )
                   
        

def run():
    cfg = dict(CONFIG)

    logger = setup_logging(cfg["log_file"])

    logger.info("=" * 60)
    logger.info("Network Monitor Started")
    logger.info(f"Interface : {cfg['interface'] or 'default'}")
    logger.info(f"Time Window : {cfg['time_window']}s")
    logger.info(f"Port Scan Threshold : {cfg['port_scan_threshold']}")
    logger.info(f"Flood Threshold : {cfg['flood_packet_threshold']}")
    logger.info(f"SYN Flood Threshold : {cfg['syn_flood_threshold']}")

    print("\n[+] Network Monitor is running...")
    print("[+] Press Ctrl + C to stop.\n")

    try:
        sniff(
            iface=cfg["interface"],
            prn=lambda pkt: analyze_packet(pkt, logger, cfg),
            store=False,
        )

    except KeyboardInterrupt:
        logger.info("Network Monitor Stopped.")
        print("\n[+] Monitoring stopped.")

    except PermissionError:
        logger.error("Run the program with sudo.")
        print("\n[-] Permission denied. Run with sudo.")

    input("\nPress Enter to continue...")