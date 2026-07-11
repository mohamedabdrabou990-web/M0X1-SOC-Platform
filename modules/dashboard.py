

from __future__ import annotations

import getpass
import json
import os
import platform
import socket
from datetime import datetime
from typing import Any, Optional

from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ==============================================================================
# Global constants
# ==============================================================================
console = Console()

REPORTS_DIR = "reports"
LOGS_DIR = "logs"
DATA_DIR = "data"

# Where an Alert Manager–style alerts.json might live. Checked in order.
ALERTS_FILE_CANDIDATES = [
    os.path.join(REPORTS_DIR, "alerts.json"),
    os.path.join(DATA_DIR, "alerts.json"),
]

# Where the Threat Intelligence IOC database lives (see threat_intelligence.py).
IOC_DB_JSON_PATH = os.path.join(DATA_DIR, "iocs.json")

# Where the last Threat Intelligence / IOC Scanner report lives (see
# threat_intelligence.py's save_report()), used for the "Last IOC Scan" panel.
THREAT_REPORT_PATH = os.path.join(REPORTS_DIR, "threat_report.json")

# Rich style per health status, used consistently across the whole screen.
STATUS_STYLES: dict[str, str] = {
    "ONLINE": "bold green",
    "EMPTY": "bold yellow",
    "OFFLINE": "bold red",
}

# Human-friendly labels for each raw health status. Folders use "Loaded" /
# datasets use "Available", per the dashboard's improved System Health copy.
FOLDER_STATUS_LABELS: dict[str, str] = {
    "ONLINE": "✔ Loaded",
    "EMPTY": "⚠ Empty",
    "OFFLINE": "✖ Missing",
}

DATASET_STATUS_LABELS: dict[str, str] = {
    "ONLINE": "✔ Available",
    "EMPTY": "⚠ Empty",
    "OFFLINE": "✖ Missing",
}

SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
}


# ==============================================================================
# LOW-LEVEL SAFE HELPERS - these never raise, only ever return a safe default
# ==============================================================================
def _safe_listdir(path: str) -> list[str]:
    """
    List a directory's contents, or an empty list if it doesn't exist /
    can't be read. Never raises.
    """
    try:
        return os.listdir(path)
    except OSError:
        return []


def _safe_list_files(path: str) -> list[str]:
    """Return only the regular files (not sub-directories) inside `path`."""
    names = _safe_listdir(path)
    files = []
    for name in names:
        full_path = os.path.join(path, name)
        try:
            if os.path.isfile(full_path):
                files.append(name)
        except OSError:
            continue
    return files


def _load_json_safely(path: str) -> Optional[Any]:
    """
    Load a JSON file's contents, returning None on any failure (missing
    file, permission error, empty file, or malformed JSON). Never raises.
    """
    try:
        with open(path, "r", encoding="utf-8") as json_file:
            content = json_file.read().strip()
            return json.loads(content) if content else None
    except (OSError, json.JSONDecodeError):
        return None


def _human_readable_size(num_bytes: int) -> str:
    """Convert a byte count into a human-friendly string (KB, MB, GB, ...)."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"  # pragma: no cover - astronomically unlikely


def _format_timestamp(epoch_seconds: float) -> str:
    """Format a Unix timestamp as a readable local date/time string."""
    try:
        return datetime.fromtimestamp(epoch_seconds).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "Unknown"


def _get_latest_files(path: str, limit: int = 5) -> list[dict[str, Any]]:
    """
    Return metadata for the `limit` most recently created files in `path`,
    sorted newest first. Returns an empty list if the folder is missing,
    empty, or unreadable.
    """
    files_info: list[dict[str, Any]] = []

    for name in _safe_list_files(path):
        full_path = os.path.join(path, name)
        try:
            file_stat = os.stat(full_path)
            files_info.append(
                {
                    "name": name,
                    "created": file_stat.st_ctime,
                    "size": file_stat.st_size,
                }
            )
        except OSError:
            continue  # Skip any file that vanished or can't be stat'd.

    files_info.sort(key=lambda entry: entry["created"], reverse=True)
    return files_info[:limit]


def clear_terminal() -> None:
    """Clear the terminal screen, on Windows or POSIX. Never raises."""
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except OSError:
        pass  # Worst case, the screen just doesn't clear - not fatal.


# ==============================================================================
# DATA COLLECTION - SYSTEM INFORMATION
# ==============================================================================
def get_system_info() -> dict[str, str]:
    """
    Collect basic host/environment information for display.

    Every individual field is wrapped so one failing lookup (e.g. hostname
    resolution) can't blank out the whole section.
    """
    now = datetime.now()

    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "Unknown"

    try:
        os_info = f"{platform.system()} {platform.release()}"
    except Exception:
        os_info = "Unknown"

    try:
        python_version = platform.python_version()
    except Exception:
        python_version = "Unknown"

    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"

    try:
        cwd = os.getcwd()
    except OSError:
        cwd = "Unknown"

    return {
        "Current Date": now.strftime("%Y-%m-%d"),
        "Current Time": now.strftime("%H:%M:%S"),
        "Hostname": hostname,
        "Operating System": os_info,
        "Python Version": python_version,
        "Current User": current_user,
        "Working Directory": cwd,
    }


# ==============================================================================
# DATA COLLECTION - PROJECT STATISTICS
# ==============================================================================
def get_project_stats() -> dict[str, int]:
    """
    Count files across reports/, logs/, and data/ for the statistics panel.
    Missing folders simply contribute 0 rather than raising.
    """
    reports_files = _safe_list_files(REPORTS_DIR)
    log_files = _safe_list_files(LOGS_DIR)
    data_files = _safe_list_files(DATA_DIR)

    json_files = [
        f for f in (reports_files + log_files + data_files)
        if f.lower().endswith(".json")
    ]

    return {
        "Number of Reports": len(reports_files),
        "Number of Log Files": len(log_files),
        "Number of JSON Files": len(json_files),
        "Total Files in reports/": len(reports_files),
        "Total Files in logs/": len(log_files),
        "Total Files in data/": len(data_files),
    }


# ==============================================================================
# DATA COLLECTION - ALERT SUMMARY
# ==============================================================================
def find_alerts_file() -> Optional[str]:
    """Return the first existing alerts.json path from the known candidates."""
    for candidate in ALERTS_FILE_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return None


def get_alert_summary() -> dict[str, Any]:
    """
    Read and summarize alerts.json (as produced by modules/alert_manager.py).

    Returns:
        dict: {"available": False} if no readable alerts.json was found,
        otherwise {"available": True, "total": int, "critical": int,
        "high": int, "medium": int, "low": int}.
    """
    alerts_path = find_alerts_file()
    if alerts_path is None:
        return {"available": False}

    alerts = _load_json_safely(alerts_path)
    if not isinstance(alerts, list):
        # File exists but is corrupted / not the expected schema.
        return {"available": False}

    summary = {"available": True, "total": len(alerts), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        severity = str(alert.get("severity", "")).strip().upper()
        if severity == "CRITICAL":
            summary["critical"] += 1
        elif severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        elif severity == "LOW":
            summary["low"] += 1

    return summary


# ==============================================================================
# DATA COLLECTION - THREAT INTELLIGENCE
# ==============================================================================
def find_ioc_database() -> Optional[str]:
    """
    Locate the IOC database: prefers data/iocs.json (the schema written by
    threat_intelligence.py), falls back to any *.txt file in data/ whose
    name suggests it's an IOC list.
    """
    if os.path.isfile(IOC_DB_JSON_PATH):
        return IOC_DB_JSON_PATH

    for name in _safe_list_files(DATA_DIR):
        if name.lower().endswith(".txt") and "ioc" in name.lower():
            return os.path.join(DATA_DIR, name)

    return None


def get_ioc_summary() -> dict[str, Any]:
    """
    Read and summarize the IOC database, supporting both the JSON schema
    ({"ips": [...], "domains": [...], "hashes": [...], "urls": [...]}) and
    a plain-text one-indicator-per-line fallback.

    Returns:
        dict: {"available": False} if no IOC database was found or it was
        unreadable, otherwise a dict with "total", "ip", "domain", "hash",
        and "url" counts.
    """
    db_path = find_ioc_database()
    if db_path is None:
        return {"available": False}

    if db_path.lower().endswith(".json"):
        data = _load_json_safely(db_path)
        if not isinstance(data, dict):
            return {"available": False}

        ips = data.get("ips", [])
        domains = data.get("domains", [])
        hashes = data.get("hashes", [])
        urls = data.get("urls", [])

        # Defensive: tolerate a malformed field (e.g. a string instead of a
        # list) by treating it as empty rather than crashing on len().
        ips = ips if isinstance(ips, list) else []
        domains = domains if isinstance(domains, list) else []
        hashes = hashes if isinstance(hashes, list) else []
        urls = urls if isinstance(urls, list) else []

        return {
            "available": True,
            "total": len(ips) + len(domains) + len(hashes) + len(urls),
            "ip": len(ips),
            "domain": len(domains),
            "hash": len(hashes),
            "url": len(urls),
        }

    # Plain-text fallback: one indicator per line, type breakdown unknown.
    try:
        with open(db_path, "r", encoding="utf-8") as txt_file:
            lines = [line.strip() for line in txt_file if line.strip()]
        return {"available": True, "total": len(lines), "ip": 0, "domain": 0, "hash": 0, "url": 0}
    except OSError:
        return {"available": False}


# ==============================================================================
# DATA COLLECTION - OVERALL SECURITY STATUS
# ==============================================================================
def get_overall_security_status(alert_summary: dict[str, Any]) -> tuple[str, str, str]:
    """
    Derive a single top-level security status from the alert summary.

    Returns:
        tuple: (emoji, label, style) where label is one of
        "SAFE" / "WARNING" / "UNDER ATTACK".
    """
    if not alert_summary.get("available") or alert_summary.get("total", 0) == 0:
        return ("🟢", "SAFE", "bold green")

    if alert_summary.get("critical", 0) > 0 or alert_summary.get("high", 0) > 0:
        return ("🔴", "UNDER ATTACK", "bold white on red")

    if alert_summary.get("medium", 0) > 0 or alert_summary.get("low", 0) > 0:
        return ("🟡", "WARNING", "bold yellow")

    return ("🟢", "SAFE", "bold green")


# ==============================================================================
# DATA COLLECTION - LATEST ALERT
# ==============================================================================
def get_latest_alert() -> Optional[dict[str, Any]]:
    """
    Return the most recent alert from alerts.json, or None if no alerts
    are available. "Most recent" is determined by the "timestamp" field
    when present, falling back to simple list order (alerts are appended
    in chronological order by alert_manager.py).
    """
    alerts_path = find_alerts_file()
    if alerts_path is None:
        return None

    alerts = _load_json_safely(alerts_path)
    if not isinstance(alerts, list) or not alerts:
        return None

    valid_alerts = [a for a in alerts if isinstance(a, dict)]
    if not valid_alerts:
        return None

    try:
        return max(valid_alerts, key=lambda a: str(a.get("timestamp", "")))
    except (TypeError, ValueError):
        return valid_alerts[-1]


# ==============================================================================
# DATA COLLECTION - LAST IOC SCAN
# ==============================================================================
def get_last_ioc_scan() -> Optional[dict[str, Any]]:
    """
    Summarize the most recent Threat Intelligence report
    (reports/threat_report.json, written by threat_intelligence.py).

    Returns:
        dict with "scan_time", "status", and "threats_found", or None if
        no report file exists or it could not be parsed.
    """
    if not os.path.isfile(THREAT_REPORT_PATH):
        return None

    report = _load_json_safely(THREAT_REPORT_PATH)
    if not isinstance(report, dict):
        return None

    iocs = report.get("iocs", [])
    if not isinstance(iocs, list):
        iocs = []

    threats_found = sum(
        1 for entry in iocs
        if isinstance(entry, dict) and str(entry.get("verdict", "")).strip().lower() == "malicious"
    )

    return {
        "scan_time": report.get("generated_at", "Unknown"),
        "status": "Completed",
        "threats_found": threats_found,
    }


# ==============================================================================
# DATA COLLECTION - SYSTEM HEALTH
# ==============================================================================
def _folder_status(path: str) -> str:
    """ONLINE if the folder exists and has files, EMPTY if it exists but is
    empty, OFFLINE if it doesn't exist at all."""
    if not os.path.isdir(path):
        return "OFFLINE"
    return "ONLINE" if _safe_list_files(path) else "EMPTY"


def _dataset_status(summary: dict[str, Any]) -> str:
    """Shared OFFLINE/EMPTY/ONLINE logic for alert & IOC summaries."""
    if not summary.get("available"):
        return "OFFLINE"
    return "ONLINE" if summary.get("total", 0) > 0 else "EMPTY"


def get_system_health(alert_summary: dict[str, Any], ioc_summary: dict[str, Any]) -> list[tuple[str, str, str]]:
    """
    Build the (component, status, kind) rows for the System Health table.

    "kind" is "folder" or "dataset" and controls which human-friendly label
    set (Loaded/Empty/Missing vs Available/Empty/Missing) is used when
    rendering, since a bare folder and a parsed dataset mean slightly
    different things even when the underlying status is the same.
    """
    return [
        ("Reports Folder", _folder_status(REPORTS_DIR), "folder"),
        ("Logs Folder", _folder_status(LOGS_DIR), "folder"),
        ("Data Folder", _folder_status(DATA_DIR), "folder"),
        ("Threat Intelligence", _dataset_status(ioc_summary), "dataset"),
        ("Alert Database", _dataset_status(alert_summary), "dataset"),
    ]


# ==============================================================================
# RENDERING - each function renders exactly one section and is called
# through _render_section() so a failure in one never blanks the others.
# ==============================================================================
def _render_section(render_func, section_name: str) -> None:
    """
    Run a section-rendering function, catching any exception so a single
    broken section prints an error panel instead of crashing the whole
    dashboard.
    """
    try:
        render_func()
    except Exception as exc:  # noqa: BLE001 - top-level safety net per section
        console.print(
            Panel(
                f"[bold red]Failed to render '{section_name}': {exc}[/bold red]",
                border_style="red",
            )
        )


def render_title() -> None:
    """Render the dashboard's main title banner."""
    title = Text("M0X1 SOC DASHBOARD", style="bold white on blue")
    subtitle = Text("Security Operations Center — Live Overview", style="italic cyan")
    header = Group(Align.center(title), Align.center(subtitle))
    console.print(Panel(header, border_style="bright_blue", padding=(1, 2)))


def render_overall_status() -> None:
    """
    Render the top-level "Overall Security Status" panel:
      🟢 SAFE          - no alerts on file
      🟡 WARNING       - only low/medium severity alerts
      🔴 UNDER ATTACK  - one or more high/critical severity alerts
    """
    alert_summary = get_alert_summary()
    emoji, label, style = get_overall_security_status(alert_summary)

    status_text = Text(f"{emoji}  {label}", style=style, justify="center")
    console.print(Panel(Align.center(status_text), title="[bold cyan]OVERALL SECURITY STATUS[/bold cyan]", border_style=style))


def render_system_info() -> Panel:
    """Build (but do not print) the System Information panel."""
    info = get_system_info()
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="bold white")
    table.add_column("Value", style="cyan")
    for label, value in info.items():
        table.add_row(label, value)
    return Panel(table, title="[bold cyan]SYSTEM INFORMATION[/bold cyan]", border_style="cyan")


def _build_stat_card(icon: str, label: str, value: Any, style: str) -> Panel:
    """
    Build a single modern 'summary card': an icon + label on top, a large
    value underneath, centered inside a colored panel.
    """
    card_content = Group(
        Align.center(Text(f"{icon}  {label}", style="bold white")),
        Align.center(Text(str(value), style=f"bold {style}")),
    )
    return Panel(card_content, border_style=style, padding=(1, 2))


def render_project_stats() -> list[Panel]:
    """
    Build (but do not print) the "Project Statistics" summary cards:
    Reports, Alerts, Logs, JSON Files, IOCs, and System Health — replacing
    the previous plain table with a modern card layout.
    """
    stats = get_project_stats()
    alert_summary = get_alert_summary()
    ioc_summary = get_ioc_summary()

    health_rows = get_system_health(alert_summary, ioc_summary)
    healthy_count = sum(1 for _, status, _ in health_rows if status == "ONLINE")
    total_components = len(health_rows)
    health_style = "green" if healthy_count == total_components else "yellow" if healthy_count > 0 else "red"

    cards_data = [
        ("📊", "Reports", stats["Number of Reports"], "cyan"),
        ("🚨", "Alerts", alert_summary.get("total", 0) if alert_summary.get("available") else 0, "red"),
        ("📝", "Logs", stats["Number of Log Files"], "yellow"),
        ("🗂", "JSON Files", stats["Number of JSON Files"], "blue"),
        ("🎯", "IOCs", ioc_summary.get("total", 0) if ioc_summary.get("available") else 0, "magenta"),
        ("💻", "System Health", f"{healthy_count}/{total_components}", health_style),
    ]

    return [_build_stat_card(icon, label, value, style) for icon, label, value, style in cards_data]


def render_overview_row() -> None:
    """Print System Information alongside the Project Statistics cards."""
    console.print(Columns([render_system_info(), *render_project_stats()], equal=True, expand=True))


def _build_latest_files_table(title: str, files: list[dict[str, Any]], empty_message: str) -> Table:
    """Shared table builder for 'Latest Reports' and 'Latest Log Files'."""
    table = Table(
        title=title,
        header_style="bold magenta",
        border_style="cyan",
        padding=(0, 2),
        pad_edge=True,
        expand=True,
    )
    table.add_column("File Name", style="white", ratio=2, overflow="fold")
    table.add_column("Created", style="yellow", justify="center", no_wrap=True)
    table.add_column("Size", style="green", justify="right", no_wrap=True)

    if not files:
        table.add_row(f"[dim]{empty_message}[/dim]", "", "")
    else:
        for file_info in files:
            table.add_row(
                file_info["name"],
                _format_timestamp(file_info["created"]),
                _human_readable_size(file_info["size"]),
            )

    return table


def render_latest_reports() -> None:
    """Print a table of the 5 most recently created files in reports/."""
    files = _get_latest_files(REPORTS_DIR, limit=5)
    console.print(_build_latest_files_table("Latest Reports", files, "No reports found."))


def render_latest_logs() -> None:
    """Print a table of the 5 most recently created files in logs/."""
    files = _get_latest_files(LOGS_DIR, limit=5)
    console.print(_build_latest_files_table("Latest Log Files", files, "No log files found."))


def render_latest_alert() -> None:
    """
    Print the "Latest Alert" panel: the single newest alert on file, with
    its time, severity, type, source, and message.
    """
    alert = get_latest_alert()

    if alert is None:
        console.print(
            Panel(
                "[yellow]No alerts available.[/yellow]",
                title="[bold cyan]LATEST ALERT[/bold cyan]",
                border_style="cyan",
            )
        )
        return

    severity = str(alert.get("severity", "UNKNOWN")).strip().upper()
    severity_style = SEVERITY_STYLES.get(severity, "white")

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="bold white")
    table.add_column("Value")
    table.add_row("Time", str(alert.get("timestamp", "Unknown")))
    table.add_row("Severity", f"[{severity_style}]{severity}[/{severity_style}]")
    table.add_row("Type", str(alert.get("alert_type", "Unknown")))
    table.add_row("Source", str(alert.get("source_module", "Unknown")))
    table.add_row("Message", str(alert.get("description", "Unknown")))

    console.print(Panel(table, title="[bold cyan]LATEST ALERT[/bold cyan]", border_style=severity_style))


def render_alert_summary() -> None:
    """Print the Alert Summary panel (totals by severity)."""
    summary = get_alert_summary()

    if not summary.get("available"):
        console.print(
            Panel(
                "[yellow]No alerts available.[/yellow]",
                title="[bold cyan]ALERT SUMMARY[/bold cyan]",
                border_style="cyan",
            )
        )
        return

    table = Table(show_header=True, header_style="bold magenta", border_style="cyan")
    table.add_column("Metric", style="white")
    table.add_column("Count", justify="right")

    table.add_row("Total Alerts", str(summary["total"]))
    table.add_row(f"[{SEVERITY_STYLES['CRITICAL']}]Critical Severity[/{SEVERITY_STYLES['CRITICAL']}]", str(summary["critical"]))
    table.add_row(f"[{SEVERITY_STYLES['HIGH']}]High Severity[/{SEVERITY_STYLES['HIGH']}]", str(summary["high"]))
    table.add_row(f"[{SEVERITY_STYLES['MEDIUM']}]Medium Severity[/{SEVERITY_STYLES['MEDIUM']}]", str(summary["medium"]))
    table.add_row(f"[{SEVERITY_STYLES['LOW']}]Low Severity[/{SEVERITY_STYLES['LOW']}]", str(summary["low"]))

    console.print(Panel(table, title="[bold cyan]ALERT SUMMARY[/bold cyan]", border_style="cyan"))


def render_last_ioc_scan() -> None:
    """
    Print the "Last IOC Scan" panel: when the last Threat Intelligence
    report was generated, its status, and how many threats it found.
    """
    scan = get_last_ioc_scan()

    if scan is None:
        console.print(
            Panel(
                "[yellow]No IOC scan available.[/yellow]",
                title="[bold cyan]LAST IOC SCAN[/bold cyan]",
                border_style="cyan",
            )
        )
        return

    threats_found = scan["threats_found"]
    threats_style = "bold red" if threats_found > 0 else "bold green"

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="bold white")
    table.add_column("Value")
    table.add_row("Last Scan Time", str(scan["scan_time"]))
    table.add_row("Status", f"[bold green]{scan['status']}[/bold green]")
    table.add_row("Threats Found", f"[{threats_style}]{threats_found}[/{threats_style}]")

    console.print(Panel(table, title="[bold cyan]LAST IOC SCAN[/bold cyan]", border_style="cyan"))


def render_threat_intelligence() -> None:
    """Print the Threat Intelligence IOC database summary panel."""
    summary = get_ioc_summary()

    if not summary.get("available"):
        console.print(
            Panel(
                "[bold red]Threat Intelligence Database Not Found[/bold red]",
                title="[bold cyan]THREAT INTELLIGENCE[/bold cyan]",
                border_style="cyan",
            )
        )
        return

    table = Table(show_header=True, header_style="bold magenta", border_style="cyan")
    table.add_column("Metric", style="white")
    table.add_column("Count", justify="right", style="bold green")

    table.add_row("IOC Count", str(summary["total"]))
    table.add_row("Hash Count", str(summary["hash"]))
    table.add_row("IP Count", str(summary["ip"]))
    table.add_row("Domain Count", str(summary["domain"]))
    table.add_row("URL Count", str(summary["url"]))

    console.print(Panel(table, title="[bold cyan]THREAT INTELLIGENCE[/bold cyan]", border_style="cyan"))


def render_system_health() -> None:
    """
    Print the improved System Health status table, using clearer
    human-friendly labels instead of raw ONLINE/OFFLINE:
        ✔ Loaded     - a folder exists and has files
        ✔ Available  - a dataset (Threat Intel / Alert DB) was parsed successfully
        ⚠ Empty      - present, but contains no data
        ✖ Missing    - not found at all
    """
    alert_summary = get_alert_summary()
    ioc_summary = get_ioc_summary()
    rows = get_system_health(alert_summary, ioc_summary)

    table = Table(title="SYSTEM HEALTH", header_style="bold magenta", border_style="cyan", padding=(0, 2))
    table.add_column("Component", style="white")
    table.add_column("Status", justify="center")

    for component, status, kind in rows:
        style = STATUS_STYLES.get(status, "white")
        labels = FOLDER_STATUS_LABELS if kind == "folder" else DATASET_STATUS_LABELS
        label = labels.get(status, status)
        table.add_row(component, f"[{style}]{label}[/{style}]")

    console.print(table)


# ==============================================================================
# ENTRY POINT
# ==============================================================================
def run() -> None:
    """
    Entry point for the SOC Dashboard.

    Renders a full-screen, read-only overview of the platform's current
    state (system info, file statistics, latest reports/logs, alerts,
    threat intelligence, and overall health), then waits for the analyst
    to press Enter before returning control to m0x1.py.

    This function is guaranteed not to raise: every section is rendered
    through _render_section(), and the final input() prompt itself is
    guarded against non-interactive environments (e.g. CI, piped input).
    """
    clear_terminal()

    _render_section(render_title, "Title")
    _render_section(render_overall_status, "Overall Security Status")
    console.print(Rule(style="bright_blue"))

    console.print(Rule("[bold cyan]SYSTEM OVERVIEW[/bold cyan]", style="cyan"))
    _render_section(render_overview_row, "System Overview")

    console.print(Rule("[bold cyan]LATEST REPORTS[/bold cyan]", style="cyan"))
    _render_section(render_latest_reports, "Latest Reports")

    console.print(Rule("[bold cyan]LATEST LOG FILES[/bold cyan]", style="cyan"))
    _render_section(render_latest_logs, "Latest Log Files")

    console.print(Rule("[bold cyan]LATEST ALERT[/bold cyan]", style="cyan"))
    _render_section(render_latest_alert, "Latest Alert")

    console.print(Rule("[bold cyan]ALERT SUMMARY[/bold cyan]", style="cyan"))
    _render_section(render_alert_summary, "Alert Summary")

    console.print(Rule("[bold cyan]LAST IOC SCAN[/bold cyan]", style="cyan"))
    _render_section(render_last_ioc_scan, "Last IOC Scan")

    console.print(Rule("[bold cyan]THREAT INTELLIGENCE[/bold cyan]", style="cyan"))
    _render_section(render_threat_intelligence, "Threat Intelligence")

    console.print(Rule("[bold cyan]SYSTEM HEALTH[/bold cyan]", style="cyan"))
    _render_section(render_system_health, "System Health")

    console.print(Rule(style="bright_blue"))

    try:
        input("\nPress Enter to return...")
    except (EOFError, KeyboardInterrupt):
        # Non-interactive environment or Ctrl+C - just return quietly.
        pass


if __name__ == "__main__":
    run()