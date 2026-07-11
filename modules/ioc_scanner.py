
from __future__ import annotations

import glob
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text

# ==============================================================================
# Integration with the existing M0X1 SOC Platform modules
# ==============================================================================
# These imports point at the platform's real shared services. They are wrapped
# in try/except purely so this file can also be imported/tested in isolation
# (e.g. in CI, or by a developer working on just this module) without the
# rest of the project present. Inside the real project these imports should
# resolve to the actual modules and the fallbacks below will simply never be
# used.

try:
    # Project-wide logging system (expected to expose get_logger(name)).
    from core.logger import get_logger  # type: ignore
except ImportError:  # pragma: no cover - standalone fallback only
    import logging

    def get_logger(name: str = "ioc_scanner"):
        """Fallback logger, mirrors the interface of the project's logger."""
        fallback_logger = logging.getLogger(name)
        if not fallback_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            )
            fallback_logger.addHandler(handler)
            fallback_logger.setLevel(logging.INFO)
        return fallback_logger

try:
    # Real, shared Alert Manager module (this is the actual integration
    # point with the rest of the M0X1 SOC Platform: modules/alert_manager.py).
    from modules.alert_manager import create_alert  # type: ignore
except ImportError:
    try:
        # Fallback for running this file directly from inside modules/
        # (e.g. `python ioc_scanner.py` from within the modules/ folder)
        # where the package-qualified import above won't resolve.
        from alert_manager import create_alert  # type: ignore
    except ImportError:  # pragma: no cover - standalone fallback only
        def create_alert(
            source_module: str, alert_type: str, description: str, severity: str = "MEDIUM"
        ) -> Dict[str, Any]:
            """
            Minimal fallback used only if modules/alert_manager.py truly
            cannot be found (e.g. this file is being tested in complete
            isolation). Mirrors create_alert's on-disk behavior closely
            enough that no data is lost, so nothing breaks once the real
            Alert Manager becomes importable again.
            """
            alert_log_path = os.path.join("logs", "alerts.log")
            os.makedirs(os.path.dirname(alert_log_path) or ".", exist_ok=True)
            alert_entry = {
                "timestamp": datetime.now().isoformat(),
                "source_module": source_module,
                "alert_type": alert_type,
                "description": description,
                "severity": severity,
            }
            with open(alert_log_path, "a", encoding="utf-8") as alert_file:
                alert_file.write(json.dumps(alert_entry) + "\n")
            return alert_entry


# ==============================================================================
# Module-level singletons
# ==============================================================================

console = Console()
logger = get_logger("ioc_scanner")

# ==============================================================================
# Paths / configuration
# ==============================================================================

REPORTS_DIR = "reports"
LOGS_DIR = "logs"

# Filenames we try first (fastest path, no directory scan needed). If none of
# these exist we fall back to a glob search so small naming differences in
# the Threat Intelligence module don't break integration.
THREAT_INTEL_REPORT_CANDIDATES: List[str] = [
    os.path.join(REPORTS_DIR, "threat_report.json"),
    os.path.join(REPORTS_DIR, "threat_intelligence.json"),
    os.path.join(REPORTS_DIR, "threat_intel_report.json"),
]
THREAT_INTEL_REPORT_GLOB = os.path.join(REPORTS_DIR, "*threat*.json")

IOC_SCAN_LOG_PATH = os.path.join(LOGS_DIR, "ioc_scan.log")


# ==============================================================================
# Verdict model
# ==============================================================================

class Verdict(str, Enum):
    """Possible outcomes of an IOC lookup."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    NOT_FOUND = "NOT FOUND"

    @property
    def rich_style(self) -> str:
        """Rich color style associated with this verdict, for consistent UI."""
        return {
            Verdict.SAFE: "bold green",
            Verdict.SUSPICIOUS: "bold yellow",
            Verdict.MALICIOUS: "bold red",
            Verdict.NOT_FOUND: "bold blue",
        }[self]

    @property
    def severity(self) -> str:
        """Alert/log severity label associated with this verdict."""
        return {
            Verdict.SAFE: "INFO",
            Verdict.SUSPICIOUS: "MEDIUM",
            Verdict.MALICIOUS: "HIGH",
            Verdict.NOT_FOUND: "INFO",
        }[self]


# Verdict thresholds used only when a matched record has a numeric
# "confidence"/"score" field but no explicit "verdict" string.
CONFIDENCE_MALICIOUS_THRESHOLD = 75
CONFIDENCE_SUSPICIOUS_THRESHOLD = 40


# ==============================================================================
# IOC type registry (the extensibility point of this module)
# ==============================================================================
# To add a new IOC type later:
#   1. Write a validator(value: str) -> bool
#   2. Add one IOCTypeDefinition entry to IOC_TYPE_REGISTRY
# Everything else (menu rendering, validation, lookup, logging) adapts
# automatically because it all iterates over this registry.

def _is_md5(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}", value))


def _is_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", value))


def _is_hash(value: str) -> bool:
    """A 'hash' IOC type accepts either MD5 or SHA256 (extend here for SHA1 etc.)."""
    return _is_md5(value) or _is_sha256(value)


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_PATTERN.match(value))


_URL_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/$.?#].[^\s]*$")


def _is_url(value: str) -> bool:
    return bool(_URL_PATTERN.match(value))


@dataclass(frozen=True)
class IOCTypeDefinition:
    """Describes one supported IOC type end-to-end."""

    key: str                                   # canonical internal key, e.g. "hash"
    label: str                                  # human label shown in menus/results
    menu_choice: str                            # the digit the user types
    validator: Callable[[str], bool]            # returns True if format is valid
    normalizer: Callable[[str], str] = field(
        default=lambda value: value.strip().lower()
    )
    # Aliases the Threat Intelligence report might use for this type.
    report_type_aliases: tuple = field(default_factory=tuple)


IOC_TYPE_REGISTRY: Dict[str, IOCTypeDefinition] = {
    "hash": IOCTypeDefinition(
        key="hash",
        label="Hash (MD5 / SHA256)",
        menu_choice="1",
        validator=_is_hash,
        report_type_aliases=("hash", "md5", "sha256", "sha1"),
    ),
    "ip": IOCTypeDefinition(
        key="ip",
        label="IPv4 Address",
        menu_choice="2",
        validator=_is_ipv4,
        report_type_aliases=("ip", "ipv4", "ip_address"),
    ),
    "domain": IOCTypeDefinition(
        key="domain",
        label="Domain",
        menu_choice="3",
        validator=_is_domain,
        # Domains are matched case-insensitively but URLs are not fully
        # lower-cased (paths can be case sensitive), so each type gets its
        # own normalizer.
        report_type_aliases=("domain", "domain_name", "fqdn"),
    ),
    "url": IOCTypeDefinition(
        key="url",
        label="URL",
        menu_choice="4",
        validator=_is_url,
        normalizer=lambda value: value.strip(),
        report_type_aliases=("url", "uri"),
    ),
}

# Reverse lookup: report "type" string (any alias) -> canonical registry key.
_ALIAS_TO_CANONICAL: Dict[str, str] = {
    alias.lower(): definition.key
    for definition in IOC_TYPE_REGISTRY.values()
    for alias in definition.report_type_aliases
}


def normalize_report_ioc_type(raw_type: str) -> Optional[str]:
    """Map a type string found in the Threat Intelligence report to a
    canonical IOC_TYPE_REGISTRY key, or None if it isn't recognized."""
    if not raw_type:
        return None
    return _ALIAS_TO_CANONICAL.get(str(raw_type).strip().lower())


# ==============================================================================
# Threat Intelligence report loading
# ==============================================================================

class ThreatIntelReportError(Exception):
    """Base class for problems with the Threat Intelligence report."""


class ThreatIntelReportMissing(ThreatIntelReportError):
    """Raised when no report file can be found at all."""


class ThreatIntelReportCorrupted(ThreatIntelReportError):
    """Raised when the report exists but is not valid/parsable JSON."""


class ThreatIntelReportEmpty(ThreatIntelReportError):
    """Raised when the report is valid JSON but contains no usable IOC data."""


def find_threat_intel_report() -> Optional[str]:
    """
    Locate the Threat Intelligence report on disk.

    Tries known filenames first, then falls back to a glob search inside
    reports/ so small naming variations don't break the integration.
    Returns the path of the newest matching file, or None if nothing is found.
    """
    for candidate_path in THREAT_INTEL_REPORT_CANDIDATES:
        if os.path.isfile(candidate_path):
            return candidate_path

    matches = glob.glob(THREAT_INTEL_REPORT_GLOB)
    if matches:
        # Prefer the most recently modified report if several exist.
        return max(matches, key=os.path.getmtime)

    return None


# Normalized index type: canonical_ioc_type -> { normalized_value -> record }
IOCIndex = Dict[str, Dict[str, Dict[str, Any]]]


def _bucket_record(index: IOCIndex, canonical_type: str, raw_value: str, record: Dict[str, Any]) -> None:
    """Insert a single IOC record into the normalized index."""
    definition = IOC_TYPE_REGISTRY.get(canonical_type)
    if definition is None or not raw_value:
        return
    normalized_value = definition.normalizer(raw_value)
    index.setdefault(canonical_type, {})[normalized_value] = record


def _ingest_flat_list(index: IOCIndex, ioc_list: Any) -> None:
    """Handle Shape A: a flat list of {"type": ..., "value": ..., ...} records."""
    if not isinstance(ioc_list, list):
        return
    for entry in ioc_list:
        if not isinstance(entry, dict):
            continue
        canonical_type = normalize_report_ioc_type(entry.get("type", ""))
        raw_value = entry.get("value") or entry.get("indicator") or ""
        if canonical_type and raw_value:
            _bucket_record(index, canonical_type, str(raw_value), entry)


def _ingest_bucketed_shape(index: IOCIndex, report_data: Dict[str, Any]) -> None:
    """Handle Shape B: top-level keys that are themselves IOC type names."""
    for raw_key, value in report_data.items():
        canonical_type = normalize_report_ioc_type(raw_key)
        if not canonical_type or not isinstance(value, list):
            continue
        for entry in value:
            if isinstance(entry, dict):
                raw_value = entry.get("value") or entry.get("indicator") or ""
                if raw_value:
                    _bucket_record(index, canonical_type, str(raw_value), entry)
            elif isinstance(entry, str):
                # Tolerate a bare list of strings with no metadata.
                _bucket_record(index, canonical_type, entry, {"value": entry})


def load_threat_intelligence_data(report_path: str) -> IOCIndex:
    """
    Load and normalize the Threat Intelligence report into an IOC index.

    Raises:
        ThreatIntelReportCorrupted: file is not valid JSON.
        ThreatIntelReportEmpty: file is valid JSON but has no usable IOCs.
    """
    try:
        with open(report_path, "r", encoding="utf-8") as report_file:
            raw_text = report_file.read()
    except OSError as os_error:
        # Treat unreadable-on-disk the same as missing; run() will report it.
        raise ThreatIntelReportMissing(str(os_error)) from os_error

    if not raw_text.strip():
        raise ThreatIntelReportEmpty("The Threat Intelligence report file is empty.")

    try:
        report_data = json.loads(raw_text)
    except json.JSONDecodeError as decode_error:
        raise ThreatIntelReportCorrupted(
            f"Could not parse report as JSON: {decode_error}"
        ) from decode_error

    index: IOCIndex = {}

    if isinstance(report_data, list):
        # Some Threat Intelligence modules may dump a bare list at top level.
        _ingest_flat_list(index, report_data)
    elif isinstance(report_data, dict):
        if isinstance(report_data.get("iocs"), list):
            _ingest_flat_list(index, report_data["iocs"])
        _ingest_bucketed_shape(index, report_data)
    else:
        raise ThreatIntelReportCorrupted("Unrecognized Threat Intelligence report structure.")

    total_iocs = sum(len(bucket) for bucket in index.values())
    if total_iocs == 0:
        raise ThreatIntelReportEmpty(
            "The Threat Intelligence report does not contain any recognizable IOC entries."
        )

    return index


# ==============================================================================
# Verdict resolution
# ==============================================================================

_VERDICT_STRING_MAP = {
    "malicious": Verdict.MALICIOUS,
    "bad": Verdict.MALICIOUS,
    "confirmed": Verdict.MALICIOUS,
    "suspicious": Verdict.SUSPICIOUS,
    "warning": Verdict.SUSPICIOUS,
    "unknown": Verdict.SUSPICIOUS,
    "safe": Verdict.SAFE,
    "clean": Verdict.SAFE,
    "benign": Verdict.SAFE,
    "whitelisted": Verdict.SAFE,
}


def determine_verdict(record: Optional[Dict[str, Any]]) -> Verdict:
    """
    Determine the verdict for a matched (or unmatched) IOC record.

    Resolution order:
      1. No record at all (IOC not present in Threat Intelligence data) ->
         NOT_FOUND. Rationale: absence of evidence is not evidence of safety;
         the scanner must say clearly that the IOC has never been analyzed,
         rather than implying it was checked and came back clean.
      2. Explicit "verdict" string on the record, if recognized.
      3. Numeric "confidence"/"score" field compared against thresholds.
      4. Fallback -> SUSPICIOUS, so an ambiguous record is never silently
         treated as fully trusted.
    """
    if record is None:
        return Verdict.NOT_FOUND

    explicit_verdict = str(record.get("verdict", "")).strip().lower()
    if explicit_verdict in _VERDICT_STRING_MAP:
        return _VERDICT_STRING_MAP[explicit_verdict]

    confidence = record.get("confidence", record.get("score"))
    if isinstance(confidence, (int, float)):
        if confidence >= CONFIDENCE_MALICIOUS_THRESHOLD:
            return Verdict.MALICIOUS
        if confidence >= CONFIDENCE_SUSPICIOUS_THRESHOLD:
            return Verdict.SUSPICIOUS
        return Verdict.SAFE

    return Verdict.SUSPICIOUS


def lookup_ioc(index: IOCIndex, ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
    """Look up a single normalized IOC value in the loaded index."""
    definition = IOC_TYPE_REGISTRY[ioc_type]
    normalized_value = definition.normalizer(value)
    bucket = index.get(ioc_type, {})

    if normalized_value in bucket:
        return bucket[normalized_value]

    # For URLs and domains, also try a substring/contains match so that, e.g.,
    # a malicious domain matches even when the user pastes a full URL, or a
    # known-bad URL still matches if the report stored only its host.
    if ioc_type in ("url", "domain"):
        for known_value, known_record in bucket.items():
            if known_value and (known_value in normalized_value or normalized_value in known_value):
                return known_record

    return None


# ==============================================================================
# Logging & alerting for scan results
# ==============================================================================

@dataclass
class ScanResult:
    """A single completed IOC scan, ready to be logged/alerted/displayed."""

    timestamp: str
    ioc_type: str
    ioc_value: str
    verdict: Verdict
    severity: str
    record: Optional[Dict[str, Any]]


def _write_scan_log_entry(result: ScanResult) -> None:
    """Append the scan result to the dedicated IOC scan log (JSON lines)."""
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        log_entry = {
            "timestamp": result.timestamp,
            "ioc_type": result.ioc_type,
            "ioc_value": result.ioc_value,
            "result": result.verdict.value,
            "severity": result.severity,
        }
        with open(IOC_SCAN_LOG_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
    except OSError as os_error:
        # Logging must never crash the scanner; report to the platform logger.
        logger.error("Failed to write IOC scan log entry: %s", os_error)


def _raise_alert_if_malicious(result: ScanResult) -> None:
    """If the verdict is MALICIOUS, notify the Alert Manager with full context."""
    if result.verdict is not Verdict.MALICIOUS:
        return

    try:
        # Fold the matched Threat Intelligence record's context (source,
        # confidence, tags) into a readable description, since the Alert
        # Manager's schema stores one free-text description per alert
        # rather than an arbitrary details dict.
        record = result.record or {}
        detail_bits = []
        source = record.get("source")
        if source:
            detail_bits.append(f"source: {source}")
        confidence = record.get("confidence", record.get("score"))
        if confidence is not None:
            detail_bits.append(f"confidence: {confidence}")
        tags = record.get("tags")
        if tags:
            detail_bits.append(f"tags: {', '.join(tags) if isinstance(tags, list) else tags}")

        description = f"{result.ioc_type.upper()} '{result.ioc_value}' matched a known-malicious indicator"
        if detail_bits:
            description += f" ({'; '.join(detail_bits)})"

        create_alert(
            source_module="IOC Scanner",
            alert_type=f"Malicious {result.ioc_type.upper()} Detected",
            description=description,
            severity="CRITICAL",
        )
        logger.warning(
            "CRITICAL alert raised for malicious %s: %s",
            result.ioc_type, result.ioc_value,
        )
    except Exception as alert_error:  # noqa: BLE001 - alerting must never crash the scan
        logger.error("Failed to raise alert for malicious IOC: %s", alert_error)


def process_scan_result(result: ScanResult) -> None:
    """Persist and, if necessary, escalate a completed scan result."""
    logger.info(
        "IOC scan: type=%s value=%s result=%s severity=%s",
        result.ioc_type, result.ioc_value, result.verdict.value, result.severity,
    )
    _write_scan_log_entry(result)
    _raise_alert_if_malicious(result)


# ==============================================================================
# Rich UI helpers
# ==============================================================================

def display_title() -> None:
    """Render the module's title banner."""
    title = Text("M0X1 SOC PLATFORM", style="bold white", justify="center")
    subtitle = Text("IOC Scanner - Indicator of Compromise Lookup", style="cyan", justify="center")
    console.print(Panel.fit(f"{title}\n{subtitle}", border_style="bright_blue", padding=(1, 6)))


def display_error(message: str) -> None:
    """Render a standardized error panel."""
    console.print(Panel(message, title="[bold red]Error[/bold red]", border_style="red"))


def display_warning(message: str) -> None:
    """Render a standardized warning panel."""
    console.print(Panel(message, title="[bold yellow]Warning[/bold yellow]", border_style="yellow"))


def display_report_missing_message() -> None:
    """Shown when no Threat Intelligence report can be found on disk."""
    display_error(
        "No Threat Intelligence report was found in the 'reports/' directory.\n\n"
        "The IOC Scanner relies entirely on data produced by the "
        "Threat Intelligence module and does not store its own IOC lists.\n\n"
        "[bold]Please run the Threat Intelligence module first[/bold] to "
        "generate a report, then re-open the IOC Scanner."
    )


def build_menu_table() -> Table:
    """Build the main menu table from the IOC_TYPE_REGISTRY (auto-extends)."""
    menu_table = Table(show_header=True, header_style="bold cyan", border_style="bright_blue")
    menu_table.add_column("Option", justify="center", width=8)
    menu_table.add_column("Action")

    for definition in sorted(IOC_TYPE_REGISTRY.values(), key=lambda d: d.menu_choice):
        menu_table.add_row(definition.menu_choice, f"Scan {definition.label}")
    menu_table.add_row("0", "Back")
    return menu_table


def display_main_menu() -> str:
    """Render the menu and return the user's raw menu choice."""
    console.print(build_menu_table())
    return Prompt.ask("\n[bold cyan]Select an option[/bold cyan]").strip()


def _menu_choice_to_ioc_type(choice: str) -> Optional[str]:
    """Translate a typed menu digit back into a canonical IOC type key."""
    for definition in IOC_TYPE_REGISTRY.values():
        if definition.menu_choice == choice:
            return definition.key
    return None


def display_result_panel(result: ScanResult) -> None:
    """Render the final SAFE / SUSPICIOUS / MALICIOUS result panel + details table."""
    verdict = result.verdict
    header = f"[{verdict.rich_style}]{verdict.value}[/{verdict.rich_style}]"

    details_table = Table(show_header=False, border_style=verdict.rich_style.split()[-1])
    details_table.add_column("Field", style="bold")
    details_table.add_column("Value")
    details_table.add_row("IOC Type", IOC_TYPE_REGISTRY[result.ioc_type].label)
    details_table.add_row("IOC Value", result.ioc_value)
    details_table.add_row("Verdict", header)
    details_table.add_row("Severity", result.severity)
    details_table.add_row("Scanned At", result.timestamp)

    if result.record:
        source = result.record.get("source")
        tags = result.record.get("tags")
        confidence = result.record.get("confidence", result.record.get("score"))
        if source:
            details_table.add_row("Source", str(source))
        if confidence is not None:
            details_table.add_row("Confidence", str(confidence))
        if tags:
            details_table.add_row("Tags", ", ".join(tags) if isinstance(tags, list) else str(tags))
    else:
        details_table.add_row("Match", "No entry found in Threat Intelligence data")

    console.print(
        Panel(
            details_table,
            title=f"[{verdict.rich_style}]Scan Result: {verdict.value}[/{verdict.rich_style}]",
            border_style=verdict.rich_style.split()[-1],
        )
    )


# ==============================================================================
# Core scan workflow
# ==============================================================================

def perform_scan(index: IOCIndex, ioc_type: str) -> None:
    """
    Prompt for a single IOC value of the given type, validate it, look it up,
    display the result, and persist logging/alerting side effects.
    """
    definition = IOC_TYPE_REGISTRY[ioc_type]
    raw_value = Prompt.ask(f"Enter {definition.label} to scan").strip()

    if not raw_value:
        display_warning("No value entered. Returning to menu.")
        return

    if not definition.validator(raw_value):
        display_error(
            f"'{raw_value}' does not look like a valid {definition.label}.\n"
            "Please check the format and try again."
        )
        return

    matched_record = lookup_ioc(index, ioc_type, raw_value)
    verdict = determine_verdict(matched_record)

    result = ScanResult(
        timestamp=datetime.now().isoformat(timespec="seconds"),
        ioc_type=ioc_type,
        ioc_value=raw_value,
        verdict=verdict,
        severity=verdict.severity,
        record=matched_record,
    )

    display_result_panel(result)
    process_scan_result(result)


def load_report_with_feedback() -> Optional[IOCIndex]:
    """
    Locate and load the Threat Intelligence report, displaying an
    appropriate Rich message for every failure mode. Returns None if the
    scanner cannot proceed.
    """
    report_path = find_threat_intel_report()
    if report_path is None:
        display_report_missing_message()
        return None

    try:
        index = load_threat_intelligence_data(report_path)
    except ThreatIntelReportEmpty:
        display_warning(
            f"The Threat Intelligence report at '{report_path}' was found but "
            "contains no usable IOC entries.\n\n"
            "Please re-run the Threat Intelligence module to populate it."
        )
        return None
    except ThreatIntelReportCorrupted as corrupt_error:
        display_error(
            f"The Threat Intelligence report at '{report_path}' appears to be "
            f"corrupted and could not be read:\n\n{corrupt_error}\n\n"
            "Please re-run the Threat Intelligence module to regenerate it."
        )
        logger.error("Corrupted Threat Intelligence report: %s", corrupt_error)
        return None
    except ThreatIntelReportMissing:
        display_report_missing_message()
        return None

    total_iocs = sum(len(bucket) for bucket in index.values())
    console.print(
        f"[green]Loaded {total_iocs} IOC record(s) from Threat Intelligence report:[/green] "
        f"[dim]{report_path}[/dim]\n"
    )
    return index


# ==============================================================================
# Module entry point
# ==============================================================================

def run() -> None:
    """
    Entry point called by the M0X1 SOC Platform's main menu.

    Loads the Threat Intelligence report once per session, then presents the
    IOC Scanner submenu in a loop until the user selects "0 - Back". All
    errors are caught and surfaced to the user without propagating out of
    this function, so a scanner failure never takes down the platform.
    """
    display_title()

    try:
        index = load_report_with_feedback()
    except Exception as unexpected_error:  # noqa: BLE001 - top-level safety net
        logger.exception("Unexpected error while loading Threat Intelligence report")
        display_error(f"An unexpected error occurred while loading the report: {unexpected_error}")
        return

    if index is None:
        # Feedback already shown by load_report_with_feedback().
        return

    while True:
        try:
            choice = display_main_menu()

            if choice == "0":
                console.print("[cyan]Returning to main menu...[/cyan]")
                return

            ioc_type = _menu_choice_to_ioc_type(choice)
            if ioc_type is None:
                display_warning(f"'{choice}' is not a valid menu option.")
                continue

            perform_scan(index, ioc_type)

        except KeyboardInterrupt:
            console.print("\n[cyan]Scan cancelled. Returning to main menu...[/cyan]")
            return
        except Exception as unexpected_error:  # noqa: BLE001 - top-level safety net
            logger.exception("Unexpected error during IOC scan")
            display_error(f"An unexpected error occurred: {unexpected_error}")
            # Loop continues -- a single bad scan should not end the session.


# Allow standalone execution for quick manual testing during development.
if __name__ == "__main__":
    run()