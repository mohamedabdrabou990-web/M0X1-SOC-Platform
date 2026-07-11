from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

# ==============================================================================
# Global constants
# ==============================================================================
console = Console()

REPORTS_DIR = "reports"
ALERTS_PATH = os.path.join(REPORTS_DIR, "alerts.json")

# Canonical severity levels, ordered from least to most urgent.
SEVERITY_LEVELS: list[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Canonical alert lifecycle states.
STATUS_LEVELS: list[str] = ["NEW", "INVESTIGATING", "RESOLVED"]

# Rich styling per severity / status, used consistently across every table
# and panel so the analyst can scan the screen by color alone.
SEVERITY_STYLES: dict[str, str] = {
    "LOW": "bold green",
    "MEDIUM": "bold yellow",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
}

STATUS_STYLES: dict[str, str] = {
    "NEW": "bold cyan",
    "INVESTIGATING": "bold yellow",
    "RESOLVED": "bold green",
}


# ==============================================================================
# INTERNAL HELPERS - storage
# ==============================================================================
def _ensure_directory(path: str) -> None:
    """
    Ensure a directory exists, creating it (and parents) if necessary.

    Args:
        path (str): Directory path to create.
    """
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        console.print(
            Panel(
                f"[bold red]Failed to create directory '{path}': {exc}[/bold red]",
                border_style="red",
            )
        )


def _utc_now_iso() -> str:
    """
    Return the current UTC timestamp in ISO-8601 format.

    Returns:
        str: Current UTC time as an ISO-8601 string.
    """
    return datetime.now(timezone.utc).isoformat()


def ensure_alerts_file() -> None:
    """
    Guarantee that reports/alerts.json exists and is valid JSON.

    Creates the 'reports/' directory and an empty alert list if the file
    is missing. If the file exists but is corrupted/unreadable, it is left
    untouched on disk (so nothing is silently destroyed) but load_alerts()
    will report the problem and return an empty list for that session.
    """
    _ensure_directory(REPORTS_DIR)

    if not os.path.exists(ALERTS_PATH):
        try:
            with open(ALERTS_PATH, "w", encoding="utf-8") as alerts_file:
                json.dump([], alerts_file, indent=4)
        except OSError as exc:
            console.print(
                Panel(
                    f"[bold red]Failed to create alerts file: {exc}[/bold red]",
                    border_style="red",
                )
            )


def load_alerts() -> list[dict[str, Any]]:
    """
    Load all alerts from reports/alerts.json.

    Returns:
        list[dict]: The list of alert records. Returns an empty list if the
        file is missing, empty, or corrupted (a warning is printed in the
        corrupted case so the analyst is aware).
    """
    ensure_alerts_file()

    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as alerts_file:
            content = alerts_file.read().strip()
            alerts = json.loads(content) if content else []
            if not isinstance(alerts, list):
                console.print(
                    "[yellow]Warning: alerts.json did not contain a list. "
                    "Treating it as empty for this session.[/yellow]"
                )
                return []
            return alerts
    except (json.JSONDecodeError, OSError) as exc:
        console.print(
            Panel(
                f"[bold red]Failed to read alerts.json: {exc}[/bold red]\n"
                "The file was left untouched on disk. Fix or remove it "
                "manually if the problem persists.",
                border_style="red",
            )
        )
        return []


def save_alerts(alerts: list[dict[str, Any]]) -> bool:
    """
    Persist the full alert list back to reports/alerts.json.

    Args:
        alerts (list[dict]): The complete, updated list of alerts to save.

    Returns:
        bool: True on success, False if the write failed.
    """
    _ensure_directory(REPORTS_DIR)

    try:
        with open(ALERTS_PATH, "w", encoding="utf-8") as alerts_file:
            json.dump(alerts, alerts_file, indent=4)
        return True
    except OSError as exc:
        console.print(
            Panel(
                f"[bold red]Failed to save alerts.json: {exc}[/bold red]",
                border_style="red",
            )
        )
        return False


def _generate_alert_id(alerts: list[dict[str, Any]]) -> str:
    """
    Generate the next sequential alert ID (e.g. "ALT-0001", "ALT-0002", ...).

    Scans existing alerts for the highest numeric suffix already in use so
    IDs stay unique and sequential even if alerts were deleted or the file
    was edited by hand.

    Args:
        alerts (list[dict]): Current alert list to scan for existing IDs.

    Returns:
        str: The next available alert ID.
    """
    highest = 0
    for alert in alerts:
        alert_id = str(alert.get("id", ""))
        if alert_id.startswith("ALT-"):
            suffix = alert_id.split("-", 1)[-1]
            if suffix.isdigit():
                highest = max(highest, int(suffix))
    return f"ALT-{highest + 1:04d}"


# ==============================================================================
# VALIDATION
# ==============================================================================
def _normalize_severity(severity: str) -> str:
    """
    Validate and normalize a severity string against SEVERITY_LEVELS.

    Args:
        severity (str): Raw severity value supplied by the caller.

    Returns:
        str: A valid entry from SEVERITY_LEVELS. Falls back to "MEDIUM" if
        the input is missing or not recognized, so a malformed call from a
        future module can never crash the Alert Manager or silently vanish.
    """
    candidate = str(severity or "").strip().upper()
    return candidate if candidate in SEVERITY_LEVELS else "MEDIUM"


def _normalize_status(status: str) -> str:
    """
    Validate and normalize a status string against STATUS_LEVELS.

    Args:
        status (str): Raw status value supplied by the caller.

    Returns:
        str: A valid entry from STATUS_LEVELS. Falls back to "NEW" if the
        input is missing or not recognized.
    """
    candidate = str(status or "").strip().upper()
    return candidate if candidate in STATUS_LEVELS else "NEW"


# ==============================================================================
# PUBLIC API - used by OTHER modules to raise alerts
# ==============================================================================
def create_alert(
    source_module: str,
    alert_type: str,
    description: str,
    severity: str = "MEDIUM",
) -> dict[str, Any]:
    """
    Create a new alert and persist it to reports/alerts.json.

    This is the single entry point every other M0X1 module should use to
    raise an alert. It is safe to call repeatedly and concurrently across
    modules: each call re-reads the current file, appends one record, and
    writes the full list back so no other module's alerts are lost.

    Args:
        source_module (str): Name of the module raising the alert
            (e.g. "Network Scanner", "IOC Scanner").
        alert_type (str): Short category for the alert
            (e.g. "Port Scan Detected", "Malicious IP").
        description (str): Human-readable explanation of what was detected.
        severity (str): One of LOW / MEDIUM / HIGH / CRITICAL. Invalid or
            missing values default to MEDIUM.

    Returns:
        dict: The alert record that was created and saved, including its
        generated "id", "timestamp", and default "status" of "NEW".
    """
    alerts = load_alerts()

    new_alert = {
        "id": _generate_alert_id(alerts),
        "timestamp": _utc_now_iso(),
        "source_module": source_module or "Unknown",
        "alert_type": alert_type or "Unspecified",
        "description": description or "",
        "severity": _normalize_severity(severity),
        "status": "NEW",
    }

    alerts.append(new_alert)
    save_alerts(alerts)

    return new_alert


def update_alert_status(alert_id: str, new_status: str) -> bool:
    """
    Update the status of a single alert by ID and persist the change.

    Args:
        alert_id (str): The alert's "id" field (e.g. "ALT-0003").
        new_status (str): One of NEW / INVESTIGATING / RESOLVED.

    Returns:
        bool: True if the alert was found and updated, False if no alert
        with that ID exists.
    """
    alerts = load_alerts()

    for alert in alerts:
        if str(alert.get("id", "")).strip().upper() == alert_id.strip().upper():
            alert["status"] = _normalize_status(new_status)
            save_alerts(alerts)
            return True

    return False


# ==============================================================================
# FILTERING
# ==============================================================================
def filter_all(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return every alert, unfiltered."""
    return alerts


def filter_high_critical(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only HIGH and CRITICAL severity alerts."""
    return [
        alert for alert in alerts
        if _normalize_severity(alert.get("severity", "")) in ("HIGH", "CRITICAL")
    ]


def search_alerts(alerts: list[dict[str, Any]], keyword: str) -> list[dict[str, Any]]:
    """
    Return alerts whose ID, source module, type, or description contain the
    given keyword (case-insensitive substring match).

    Args:
        alerts (list[dict]): Alerts to search within.
        keyword (str): Free-text search term.

    Returns:
        list[dict]: Matching alerts, in original order.
    """
    needle = keyword.strip().lower()
    if not needle:
        return alerts

    matches = []
    for alert in alerts:
        haystack = " ".join(
            str(alert.get(field, ""))
            for field in ("id", "source_module", "alert_type", "description")
        ).lower()
        if needle in haystack:
            matches.append(alert)

    return matches


# ==============================================================================
# RICH UI HELPERS
# ==============================================================================
def display_title() -> None:
    """Render the Alert Manager title banner."""
    console.print(
        Panel(
            "[bold white]M0X1 SOC PLATFORM[/bold white]\n"
            "[cyan]Alert Manager - Detection & Incident Tracking[/cyan]",
            border_style="bright_blue",
            expand=False,
        )
    )


def display_error(message: str) -> None:
    """Render a standardized error panel."""
    console.print(Panel(message, title="[bold red]Error[/bold red]", border_style="red"))


def display_warning(message: str) -> None:
    """Render a standardized warning panel."""
    console.print(Panel(message, title="[bold yellow]Warning[/bold yellow]", border_style="yellow"))


def display_success(message: str) -> None:
    """Render a standardized success panel."""
    console.print(Panel(message, title="[bold green]Success[/bold green]", border_style="green"))


def build_alerts_table(alerts: list[dict[str, Any]], title: str) -> Table:
    """
    Build a Rich table for a list of alerts.

    Args:
        alerts (list[dict]): Alerts to render, one per row.
        title (str): Title shown at the top of the table.

    Returns:
        Table: A fully populated Rich Table ready to print.
    """
    table = Table(
        title=title,
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Timestamp", style="white", no_wrap=True)
    table.add_column("Source Module", style="white")
    table.add_column("Alert Type", style="white")
    table.add_column("Description", style="white", overflow="fold")
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)

    for alert in alerts:
        severity = _normalize_severity(alert.get("severity", ""))
        status = _normalize_status(alert.get("status", ""))

        severity_style = SEVERITY_STYLES.get(severity, "white")
        status_style = STATUS_STYLES.get(status, "white")

        table.add_row(
            str(alert.get("id", "N/A")),
            str(alert.get("timestamp", "N/A")),
            str(alert.get("source_module", "N/A")),
            str(alert.get("alert_type", "N/A")),
            str(alert.get("description", "N/A")),
            f"[{severity_style}]{severity}[/{severity_style}]",
            f"[{status_style}]{status}[/{status_style}]",
        )

    return table


def display_alerts(alerts: list[dict[str, Any]], title: str) -> None:
    """
    Print a table of alerts, or a friendly message if the list is empty.

    Args:
        alerts (list[dict]): Alerts to display.
        title (str): Title for the table.
    """
    if not alerts:
        display_warning("No alerts match this view.")
        return

    console.print(build_alerts_table(alerts, title))
    console.print(f"\n[dim]Total: {len(alerts)} alert(s)[/dim]\n")


# ==============================================================================
# MENU ACTIONS
# ==============================================================================
def action_show_all() -> None:
    """Display every alert currently on file."""
    alerts = load_alerts()
    display_alerts(filter_all(alerts), "All Alerts")


def action_show_high_critical() -> None:
    """Display only HIGH and CRITICAL severity alerts."""
    alerts = load_alerts()
    display_alerts(filter_high_critical(alerts), "HIGH & CRITICAL Alerts")


def action_search() -> None:
    """Prompt for a keyword and display matching alerts."""
    keyword = Prompt.ask("[bold cyan]Enter search keyword[/bold cyan]").strip()

    if not keyword:
        display_warning("No keyword entered. Returning to menu.")
        return

    alerts = load_alerts()
    matches = search_alerts(alerts, keyword)
    display_alerts(matches, f"Search Results: '{keyword}'")


def action_update_status() -> None:
    """
    Prompt for an alert ID and a new status, then apply and persist the
    update. Shows the current alert list first so the analyst can pick an
    ID without leaving the screen.
    """
    alerts = load_alerts()
    if not alerts:
        display_warning("There are no alerts to update.")
        return

    console.print(build_alerts_table(alerts, "Current Alerts"))

    alert_id = Prompt.ask("\n[bold cyan]Enter the Alert ID to update[/bold cyan]").strip()

    matching_alert = next(
        (a for a in alerts if str(a.get("id", "")).strip().upper() == alert_id.upper()),
        None,
    )
    if matching_alert is None:
        display_error(f"No alert found with ID '{alert_id}'.")
        return

    new_status = Prompt.ask(
        "[bold cyan]New status[/bold cyan]",
        choices=STATUS_LEVELS,
        show_choices=True,
    ).strip().upper()

    if update_alert_status(alert_id, new_status):
        display_success(f"Alert '{alert_id}' status updated to [bold]{new_status}[/bold].")
    else:
        display_error(f"Failed to update alert '{alert_id}'.")


# ==============================================================================
# MENU / ENTRY POINT
# ==============================================================================
def show_menu() -> None:
    """Display the Alert Manager menu inside a Rich Panel."""
    menu_text = (
        "[bold cyan]1.[/bold cyan] Show All Alerts\n"
        "[bold cyan]2.[/bold cyan] Show HIGH & CRITICAL Alerts\n"
        "[bold cyan]3.[/bold cyan] Search Alerts by Keyword\n"
        "[bold cyan]4.[/bold cyan] Update Alert Status\n"
        "[bold cyan]0.[/bold cyan] Back"
    )
    console.print(
        Panel(
            menu_text,
            title="[bold white]ALERT MANAGER[/bold white]",
            border_style="bright_blue",
            expand=False,
        )
    )


def run() -> None:
    """
    Entry point for the Alert Manager module.

    Ensures alerts.json exists, then displays the menu in a loop and
    dispatches user choices to the appropriate handler functions until the
    user selects '0' to return to the main menu, or interrupts execution
    with Ctrl+C.
    """
    ensure_alerts_file()
    display_title()

    while True:
        try:
            show_menu()
            choice = Prompt.ask(
                "[bold green]Select an option[/bold green]",
                choices=["0", "1", "2", "3", "4"],
                show_choices=False,
            )

            if choice == "1":
                action_show_all()
            elif choice == "2":
                action_show_high_critical()
            elif choice == "3":
                action_search()
            elif choice == "4":
                action_update_status()
            elif choice == "0":
                console.print("[bold yellow]Returning to main menu...[/bold yellow]")
                break

        except KeyboardInterrupt:
            console.print(
                "\n[bold red]Operation interrupted by user (Ctrl+C).[/bold red]"
            )
            break
        except Exception as exc:  # noqa: BLE001 - top-level safety net for the module
            console.print(
                Panel(
                    f"[bold red]Unexpected error in Alert Manager module: {exc}[/bold red]",
                    border_style="red",
                )
            )


if __name__ == "__main__":
    run()