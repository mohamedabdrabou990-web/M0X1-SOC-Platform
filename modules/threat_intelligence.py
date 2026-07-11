
from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

# --------------------------------------------------------------------------
# Import the lazy API key loader from config.py (never hardcoded in-module).
# get_vt_api_key() is only called later, right before a VirusTotal request
# is made, so simply importing/opening this module never prompts for a key.
# prompt_new_vt_api_key() is used to silently recover from an invalid key
# (HTTP 401) without ever telling the user to edit .env by hand.
# --------------------------------------------------------------------------
try:
    from config import get_vt_api_key, prompt_new_vt_api_key  # type: ignore
except ImportError:
    def get_vt_api_key() -> str | None:  # type: ignore
        """Fallback used only if config.py truly cannot be found."""
        return None

    def prompt_new_vt_api_key() -> str | None:  # type: ignore
        """Fallback used only if config.py truly cannot be found."""
        return None

# --------------------------------------------------------------------------
# Integration with the Alert Manager module. Every malicious verdict found
# during a lookup is forwarded here so it shows up in reports/alerts.json
# alongside alerts raised by other modules (IOC Scanner, etc).
# --------------------------------------------------------------------------
try:
    from modules.alert_manager import create_alert  # type: ignore
except ImportError:
    try:
        # Fallback for running this file directly from inside modules/.
        from alert_manager import create_alert  # type: ignore
    except ImportError:  # pragma: no cover - standalone fallback only
        def create_alert(
            source_module: str, alert_type: str, description: str, severity: str = "MEDIUM"
        ) -> dict[str, Any]:
            """
            Minimal fallback used only if modules/alert_manager.py truly
            cannot be found. Keeps this module usable in isolation without
            losing alert data once the real Alert Manager is importable.
            """
            _ensure_directory("logs")
            alert_entry = {
                "timestamp": _utc_now_iso(),
                "source_module": source_module,
                "alert_type": alert_type,
                "description": description,
                "severity": severity,
            }
            with open(os.path.join("logs", "alerts.log"), "a", encoding="utf-8") as alert_file:
                alert_file.write(json.dumps(alert_entry) + "\n")
            return alert_entry

# --------------------------------------------------------------------------
# Global constants
# --------------------------------------------------------------------------
console = Console()

VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15  # seconds

# Cached in-memory once the key has been resolved for this run, so we don't
# re-read the .env file on every single lookup inside the same session.
_API_KEY_CACHE: str | None = None

DATA_DIR = "data"
IOC_DB_PATH = os.path.join(DATA_DIR, "iocs.json")

REPORTS_DIR = "reports"
REPORT_PATH = os.path.join(REPORTS_DIR, "threat_report.json")

MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


# ==============================================================================
# VALIDATION FUNCTIONS
# ==============================================================================
def validate_ip(ip_address: str) -> bool:
    """
    Validate whether a given string is a properly formatted IPv4 or IPv6 address.

    Args:
        ip_address (str): The IP address to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_address.strip())
        return True
    except (ValueError, AttributeError):
        return False


def validate_domain(domain: str) -> bool:
    """
    Validate whether a given string is a properly formatted domain name.

    Args:
        domain (str): The domain name to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    if not domain:
        return False
    return bool(DOMAIN_REGEX.match(domain.strip()))


def validate_hash(file_hash: str) -> bool:
    """
    Validate whether a given string is a valid MD5 or SHA256 hash.

    Args:
        file_hash (str): The hash string to validate.

    Returns:
        bool: True if valid MD5 or SHA256, False otherwise.
    """
    if not file_hash:
        return False
    file_hash = file_hash.strip()
    return bool(MD5_REGEX.match(file_hash) or SHA256_REGEX.match(file_hash))


# ==============================================================================
# INTERNAL HELPERS
# ==============================================================================
def _get_api_key() -> str | None:
    """
    Resolve the VirusTotal API key, prompting the user only if it is not
    already stored in the .env file. The result is cached in-memory for the
    rest of the session so it is only looked up / prompted for once.

    Returns:
        str | None: The API key if available, None if missing/cancelled.
    """
    global _API_KEY_CACHE

    if _API_KEY_CACHE:
        return _API_KEY_CACHE

    try:
        api_key = get_vt_api_key()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold red]API key entry cancelled.[/bold red]")
        return None

    if not api_key or api_key.strip().upper() == "YOUR_API_KEY":
        console.print(
            Panel(
                "[bold red]VirusTotal API key not configured.[/bold red]",
                title="[bold red]Configuration Error",
                border_style="red",
            )
        )
        return None

    _API_KEY_CACHE = api_key
    return api_key


def _vt_get(endpoint: str, api_key: str, _allow_retry: bool = True) -> dict[str, Any] | None:
    """
    Perform a GET request against the VirusTotal API with unified error handling.

    If VirusTotal responds with HTTP 401 (invalid API key), the user is
    prompted right here for a new key (hidden input), the .env file is
    updated automatically, and the original request is retried exactly
    once with the new key. The user is never told to edit .env manually.

    Args:
        endpoint (str): API endpoint path (appended to VT_BASE_URL).
        api_key (str): The VirusTotal API key to authenticate the request.
        _allow_retry (bool): Internal flag - False on the retry attempt so
            we never loop more than once.

    Returns:
        dict | None: Parsed JSON response on success, None on failure.
    """
    global _API_KEY_CACHE

    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}{endpoint}"

    try:
        with console.status(
            "[bold cyan]Querying VirusTotal API...[/bold cyan]", spinner="dots"
        ):
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        # ---- HTTP status handling -------------------------------------------------
        if response.status_code == 401:
            if not _allow_retry:
                # This was already the retry attempt with a freshly entered key.
                console.print(
                    Panel(
                        "[bold red]Authentication failed again with the new API "
                        "key.[/bold red]\nPlease verify your VirusTotal account "
                        "and try again later.",
                        title="Authentication Error",
                        border_style="red",
                    )
                )
                return None

            console.print(
                Panel(
                    "[bold red]Invalid API Key.[/bold red]\n"
                    "Your VirusTotal API key was rejected.",
                    title="Authentication Error",
                    border_style="red",
                )
            )

            try:
                new_api_key = prompt_new_vt_api_key()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[bold red]API key entry cancelled.[/bold red]")
                return None

            if not new_api_key:
                console.print(
                    Panel(
                        "[bold red]No new API key provided.[/bold red]",
                        title="Authentication Error",
                        border_style="red",
                    )
                )
                return None

            # Keep the in-session cache in sync with the freshly saved key.
            _API_KEY_CACHE = new_api_key

            # Retry the exact same request once, with the new key.
            return _vt_get(endpoint, new_api_key, _allow_retry=False)

        if response.status_code == 404:
            console.print(
                Panel(
                    "[bold yellow]No data found for this indicator.[/bold yellow]",
                    title="Not Found",
                    border_style="yellow",
                )
            )
            return None

        if response.status_code == 429:
            console.print(
                Panel(
                    "[bold red]API Rate Limit Exceeded.[/bold red]\n"
                    "Please wait before making additional requests.",
                    title="Rate Limit",
                    border_style="red",
                )
            )
            return None

        response.raise_for_status()
        return response.json()

    except requests.exceptions.ConnectTimeout:
        console.print(
            Panel(
                "[bold red]Connection timed out while contacting VirusTotal.[/bold red]",
                title="Timeout Error",
                border_style="red",
            )
        )
    except requests.exceptions.ConnectionError:
        console.print(
            Panel(
                "[bold red]No internet connection available.[/bold red]\n"
                "Please check your network and try again.",
                title="Connection Error",
                border_style="red",
            )
        )
    except requests.exceptions.RequestException as exc:
        console.print(
            Panel(
                f"[bold red]Unexpected API error:[/bold red] {exc}",
                title="Request Error",
                border_style="red",
            )
        )
    except json.JSONDecodeError:
        console.print(
            Panel(
                "[bold red]Failed to parse VirusTotal response.[/bold red]",
                title="Parsing Error",
                border_style="red",
            )
        )

    return None


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


# ==============================================================================
# REPORTING
# ==============================================================================
def save_report(entry_type: str, query: str, malicious: int) -> None:
    """
    Append a lookup entry to reports/threat_report.json.

    Args:
        entry_type (str): Type of lookup ("IP", "Domain", "Hash").
        query (str): The value that was queried.
        malicious (int): Number of malicious detections found.
    """
    _ensure_directory(REPORTS_DIR)

    report_entry = {
    "type": entry_type.lower(),
    "value": query,
    "verdict": "malicious" if malicious > 0 else "safe",
    "confidence": malicious,
    "source": "VirusTotal",
    "tags": [],
    "time": _utc_now_iso()
    }

    reports: list[dict[str, Any]] = []

    try:
        if os.path.exists(REPORT_PATH):
            with open(REPORT_PATH, "r", encoding="utf-8") as report_file:
                content = report_file.read().strip()
                existing_report = json.loads(content) if content else {}
                if isinstance(existing_report, dict):
                    reports = existing_report.get("iocs", [])
                    if not isinstance(reports, list):
                        reports = []
                elif isinstance(existing_report, list):
                    # Legacy flat-list format from a previous version of the
                    # report file; migrate its entries into the new schema.
                    reports = existing_report
    except (json.JSONDecodeError, OSError):
        # If the report file is corrupted or unreadable, start fresh but
        # do not silently destroy the operator's ability to know something
        # went wrong.
        console.print(
            "[yellow]Warning: existing report file was unreadable. "
            "Starting a new report list.[/yellow]"
        )
        reports = []

    reports.append(report_entry)

    report_document = {
        "generated_at": _utc_now_iso(),
        "iocs": reports,
    }

    try:
        with open(REPORT_PATH, "w", encoding="utf-8") as report_file:
            json.dump(report_document, report_file, indent=4)
    except OSError as exc:
        console.print(
            Panel(
                f"[bold red]Failed to save report: {exc}[/bold red]",
                border_style="red",
            )
        )

    # ----------------------------------------------------------------------
    # Alert Manager integration: any malicious verdict is forwarded to the
    # shared Alert Manager so it appears in reports/alerts.json alongside
    # alerts raised by the IOC Scanner and any future module.
    # ----------------------------------------------------------------------
    if malicious > 0:
        severity = "CRITICAL" if malicious >= 5 else "HIGH"
        try:
            create_alert(
                source_module="Threat Intelligence",
                alert_type=f"Malicious {entry_type} Detected",
                description=(
                    f"{entry_type} '{query}' flagged malicious by VirusTotal "
                    f"({malicious} engine(s) reported it as malicious)."
                ),
                severity=severity,
            )
        except Exception as alert_error:  # noqa: BLE001 - alerting must never crash a lookup
            console.print(
                f"[yellow]Warning: failed to raise alert for '{query}': {alert_error}[/yellow]"
            )


# ==============================================================================
# IOC DATABASE MANAGEMENT
# ==============================================================================
def update_ioc_database() -> None:
    """
    Update (or create) the local IOC database at data/iocs.json.

    Behavior:
        - Creates the 'data/' folder if it does not exist.
        - Creates 'iocs.json' with the base schema if it does not exist.
        - If the file already exists, preserves existing entries and
          only refreshes the 'updated' timestamp (VirusTotal's public
          API has no bulk-IOC-feed endpoint on the free tier).
    """
    _ensure_directory(DATA_DIR)

    ioc_data: dict[str, Any] = {
        "updated": _utc_now_iso(),
        "ips": [],
        "domains": [],
        "hashes": [],
    }

    try:
        if os.path.exists(IOC_DB_PATH):
            with open(IOC_DB_PATH, "r", encoding="utf-8") as ioc_file:
                content = ioc_file.read().strip()
                existing_data = json.loads(content) if content else {}

            # Preserve existing lists, only refresh the timestamp.
            ioc_data["ips"] = existing_data.get("ips", [])
            ioc_data["domains"] = existing_data.get("domains", [])
            ioc_data["hashes"] = existing_data.get("hashes", [])

        with open(IOC_DB_PATH, "w", encoding="utf-8") as ioc_file:
            json.dump(ioc_data, ioc_file, indent=4)

        console.print(
            Panel(
                f"[bold green]IOC database updated successfully.[/bold green]\n"
                f"Path: [cyan]{IOC_DB_PATH}[/cyan]\n"
                f"Last Updated: [yellow]{ioc_data['updated']}[/yellow]\n"
                f"Total IPs: {len(ioc_data['ips'])} | "
                f"Total Domains: {len(ioc_data['domains'])} | "
                f"Total Hashes: {len(ioc_data['hashes'])}",
                title="IOC Database",
                border_style="green",
            )
        )

    except (OSError, json.JSONDecodeError) as exc:
        console.print(
            Panel(
                f"[bold red]Failed to update IOC database: {exc}[/bold red]",
                border_style="red",
            )
        )


# ==============================================================================
# OPTION 1 - IP REPUTATION
# ==============================================================================
def check_ip() -> None:
    """
    Prompt the user for an IP address, query VirusTotal, and display
    a full reputation report inside a Rich Table.
    """
    ip_address = Prompt.ask("[bold cyan]Enter IP address to check[/bold cyan]").strip()

    if not validate_ip(ip_address):
        console.print(
            Panel(
                f"[bold red]Invalid IP address:[/bold red] {ip_address}",
                border_style="red",
            )
        )
        return

    api_key = _get_api_key()
    if not api_key:
        return

    result = _vt_get(f"/ip_addresses/{ip_address}", api_key)
    if result is None:
        return

    try:
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        country = attributes.get("country", "N/A")
        asn = attributes.get("asn", "N/A")
        reputation = attributes.get("reputation", 0)
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        last_analysis_ts = attributes.get("last_analysis_date")
        last_analysis_date = (
            datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            if last_analysis_ts
            else "N/A"
        )

        table = Table(
            title=f"IP Reputation Report: {ip_address}",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        table.add_row("IP Address", ip_address)
        table.add_row("Country", str(country))
        table.add_row("ASN", str(asn))
        table.add_row("Reputation", str(reputation))
        table.add_row("Malicious Detections", str(malicious))
        table.add_row("Suspicious Count", str(suspicious))
        table.add_row("Harmless Count", str(harmless))
        table.add_row("Last Analysis Date", last_analysis_date)

        console.print(table)
        save_report("IP", ip_address, malicious)

    except (KeyError, AttributeError, TypeError) as exc:
        console.print(
            Panel(
                f"[bold red]Failed to parse VirusTotal response: {exc}[/bold red]",
                border_style="red",
            )
        )


# ==============================================================================
# OPTION 2 - DOMAIN REPUTATION
# ==============================================================================
def check_domain() -> None:
    """
    Prompt the user for a domain name, query VirusTotal, and display
    a full reputation report inside a Rich Table.
    """
    domain = Prompt.ask("[bold cyan]Enter domain to check[/bold cyan]").strip()

    if not validate_domain(domain):
        console.print(
            Panel(
                f"[bold red]Invalid domain name:[/bold red] {domain}",
                border_style="red",
            )
        )
        return

    api_key = _get_api_key()
    if not api_key:
        return

    result = _vt_get(f"/domains/{domain}", api_key)
    if result is None:
        return

    try:
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        reputation = attributes.get("reputation", 0)
        categories = attributes.get("categories", {})
        categories_str = ", ".join(set(categories.values())) if categories else "N/A"
        registrar = attributes.get("registrar", "N/A")

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        last_analysis_ts = attributes.get("last_analysis_date")
        last_analysis_date = (
            datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            if last_analysis_ts
            else "N/A"
        )

        table = Table(
            title=f"Domain Reputation Report: {domain}",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        table.add_row("Domain", domain)
        table.add_row("Reputation", str(reputation))
        table.add_row("Categories", categories_str)
        table.add_row("Registrar", str(registrar))
        table.add_row("Last Analysis", last_analysis_date)
        table.add_row("Malicious Count", str(malicious))
        table.add_row("Suspicious Count", str(suspicious))

        console.print(table)
        save_report("Domain", domain, malicious)

    except (KeyError, AttributeError, TypeError) as exc:
        console.print(
            Panel(
                f"[bold red]Failed to parse VirusTotal response: {exc}[/bold red]",
                border_style="red",
            )
        )


# ==============================================================================
# OPTION 3 - FILE HASH REPUTATION
# ==============================================================================
def check_hash() -> None:
    """
    Prompt the user for an MD5 or SHA256 hash, query VirusTotal, and
    display a full reputation report inside a Rich Table.
    """
    file_hash = Prompt.ask(
        "[bold cyan]Enter file hash (MD5 or SHA256) to check[/bold cyan]"
    ).strip()

    if not validate_hash(file_hash):
        console.print(
            Panel(
                f"[bold red]Invalid hash format:[/bold red] {file_hash}",
                border_style="red",
            )
        )
        return

    api_key = _get_api_key()
    if not api_key:
        return

    result = _vt_get(f"/files/{file_hash}", api_key)
    if result is None:
        return

    try:
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        file_type = attributes.get("type_description", "N/A")
        file_size = attributes.get("size", "N/A")

        malicious = stats.get("malicious", 0)
        total_engines = sum(stats.values()) if stats else 0
        detection_ratio = f"{malicious}/{total_engines}" if total_engines else "N/A"

        first_submission_ts = attributes.get("first_submission_date")
        first_submission_date = (
            datetime.fromtimestamp(first_submission_ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            if first_submission_ts
            else "N/A"
        )

        last_analysis_ts = attributes.get("last_analysis_date")
        last_analysis_date = (
            datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            if last_analysis_ts
            else "N/A"
        )

        table = Table(
            title=f"File Hash Reputation Report: {file_hash}",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        table.add_row("File Hash", file_hash)
        table.add_row("File Type", str(file_type))
        table.add_row("File Size", f"{file_size} bytes" if file_size != "N/A" else "N/A")
        table.add_row("Detection Ratio", detection_ratio)
        table.add_row("Malicious Engines", str(malicious))
        table.add_row("First Submission Date", first_submission_date)
        table.add_row("Last Analysis Date", last_analysis_date)

        console.print(table)
        save_report("Hash", file_hash, malicious)

    except (KeyError, AttributeError, TypeError) as exc:
        console.print(
            Panel(
                f"[bold red]Failed to parse VirusTotal response: {exc}[/bold red]",
                border_style="red",
            )
        )


# ==============================================================================
# MENU / ENTRY POINT
# ==============================================================================
def show_menu() -> None:
    """
    Display the Threat Intelligence menu inside a Rich Panel.
    """
    menu_text = (
        "[bold cyan]1.[/bold cyan] Check IP Reputation\n"
        "[bold cyan]2.[/bold cyan] Check Domain Reputation\n"
        "[bold cyan]3.[/bold cyan] Check File Hash Reputation\n"
        "[bold cyan]4.[/bold cyan] Update IOC Database\n"
        "[bold cyan]0.[/bold cyan] Back"
    )
    console.print(
        Panel(
            menu_text,
            title="[bold white]THREAT INTELLIGENCE[/bold white]",
            border_style="bright_blue",
            expand=False,
        )
    )


def run() -> None:
    """
    Entry point for the Threat Intelligence module.

    As soon as this module is opened, it checks whether the VirusTotal API
    key is configured. If it is not, the user is prompted for it right here
    (once) before the menu is shown - lookups later in the session then
    reuse the cached key without prompting again.

    Displays the menu in a loop and dispatches user choices to the
    appropriate handler functions until the user selects '0' to return
    to the previous menu, or interrupts execution with Ctrl+C.
    """
    if _get_api_key() is None:
        console.print(
            Panel(
                "[bold yellow]Continuing without a valid VirusTotal API key.[/bold yellow]\n"
                "You can still use [cyan]Update IOC Database[/cyan], but lookups "
                "will fail until a valid key is provided.",
                border_style="yellow",
            )
        )

    while True:
        try:
            show_menu()
            choice = Prompt.ask(
                "[bold green]Select an option[/bold green]",
                choices=["0", "1", "2", "3", "4"],
                show_choices=False,
            )

            if choice == "1":
                check_ip()
            elif choice == "2":
                check_domain()
            elif choice == "3":
                check_hash()
            elif choice == "4":
                update_ioc_database()
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
                    f"[bold red]Unexpected error in Threat Intelligence module: {exc}[/bold red]",
                    border_style="red",
                )
            )


if __name__ == "__main__":
    run()