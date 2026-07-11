
from __future__ import annotations

import math
import os
from datetime import datetime
from typing import Any, Optional

from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ==============================================================================
# Global constants
# ==============================================================================
console = Console()

REPORTS_DIR = "reports"

# Reading an entire report into memory is fine for typical SOC report sizes,
# but a defensive cap keeps a stray multi-gigabyte file from hanging the
# terminal or exhausting memory when someone chooses to view it.
MAX_VIEW_BYTES = 2_000_000  # 2 MB
LINES_PER_PAGE = 40

# Recognized report type labels, matched by filename keyword or extension.
REPORT_TYPES = (
    "IOC Report",
    "Threat Intelligence",
    "Alert Report",
    "Log Report",
    "JSON",
    "TXT",
    "Unknown",
)


# ==============================================================================
# LOW-LEVEL SAFE HELPERS - these never raise, only ever return a safe default
# ==============================================================================
def _safe_listdir(path: str) -> list[str]:
    """List a directory's contents, or [] if missing/unreadable. Never raises."""
    try:
        return os.listdir(path)
    except OSError:
        return []


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


def clear_terminal() -> None:
    """Clear the terminal screen, on Windows or POSIX. Never raises."""
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except OSError:
        pass


def _render_section(render_func, section_name: str) -> None:
    """
    Run a section-rendering function, catching any exception so a single
    broken section prints an error panel instead of crashing the module.
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


# ==============================================================================
# REPORT TYPE DETECTION
# ==============================================================================
def _detect_report_type(filename: str) -> str:
    """
    Guess a report's type from its filename, checking content-style
    keywords before falling back to a plain extension-based label.

    Returns one of the labels in REPORT_TYPES.
    """
    lower_name = filename.lower()
    _, ext = os.path.splitext(lower_name)

    if "ioc" in lower_name:
        return "IOC Report"
    if "threat" in lower_name:
        return "Threat Intelligence"
    if "alert" in lower_name:
        return "Alert Report"
    if "log" in lower_name:
        return "Log Report"
    if ext == ".json":
        return "JSON"
    if ext == ".txt":
        return "TXT"
    return "Unknown"


# ==============================================================================
# DATA COLLECTION
# ==============================================================================
def get_reports() -> list[dict[str, Any]]:
    """
    Scan reports/ and build a fresh list of report records, sorted newest
    first. Each record gets a session-local sequential "id" (1, 2, 3, ...)
    used to reference it from the menu. Returns [] if the folder is
    missing, empty, or unreadable - never raises.
    """
    if not os.path.isdir(REPORTS_DIR):
        return []

    entries: list[dict[str, Any]] = []
    for name in _safe_listdir(REPORTS_DIR):
        full_path = os.path.join(REPORTS_DIR, name)
        try:
            if not os.path.isfile(full_path):
                continue
            file_stat = os.stat(full_path)
            entries.append(
                {
                    "name": name,
                    "path": full_path,
                    "type": _detect_report_type(name),
                    "created": file_stat.st_ctime,
                    "modified": file_stat.st_mtime,
                    "size": file_stat.st_size,
                }
            )
        except OSError:
            continue  # Skip any file that vanished or can't be stat'd.

    entries.sort(key=lambda entry: entry["created"], reverse=True)
    for index, entry in enumerate(entries, start=1):
        entry["id"] = index

    return entries


def _find_report_by_id(reports: list[dict[str, Any]], raw_id: str) -> Optional[dict[str, Any]]:
    """Resolve a user-typed ID string to a report record, or None if invalid."""
    try:
        report_id = int(raw_id)
    except (TypeError, ValueError):
        return None

    for entry in reports:
        if entry["id"] == report_id:
            return entry
    return None


# ==============================================================================
# RENDERING - LIST / SUMMARY / MENU
# ==============================================================================
def render_title() -> None:
    """Render the Reports Center's main title banner."""
    title = Text("M0X1 SOC REPORTS CENTER", style="bold white on blue")
    console.print(Panel(Align.center(title), border_style="bright_blue", padding=(1, 2)))


def render_summary(reports: list[dict[str, Any]]) -> None:
    """Print small at-a-glance cards: total report count and total size."""
    total_count = len(reports)
    total_size = sum(entry["size"] for entry in reports)

    count_panel = Panel(
        Align.center(Text(f"📄 Total Reports\n{total_count}", style="bold cyan", justify="center")),
        border_style="cyan",
    )
    size_panel = Panel(
        Align.center(Text(f"💾 Total Size\n{_human_readable_size(total_size)}", style="bold green", justify="center")),
        border_style="green",
    )
    console.print(Columns([count_panel, size_panel], equal=True, expand=True))


def _build_report_table(reports: list[dict[str, Any]], title: str = "Reports") -> Table:
    """Build (but do not print) a Rich table listing report records."""
    table = Table(title=title, header_style="bold magenta", border_style="cyan", padding=(0, 1), expand=True)
    table.add_column("ID", style="bold white", justify="center", no_wrap=True)
    table.add_column("Report Name", style="white", ratio=2, overflow="fold")
    table.add_column("Type", style="yellow", no_wrap=True)
    table.add_column("Created", style="cyan", no_wrap=True)
    table.add_column("Size", style="green", justify="right", no_wrap=True)

    if not reports:
        table.add_row("[dim]No reports found.[/dim]", "", "", "", "")
    else:
        for entry in reports:
            table.add_row(
                str(entry["id"]),
                entry["name"],
                entry["type"],
                _format_timestamp(entry["created"]),
                _human_readable_size(entry["size"]),
            )

    return table


def render_report_list(reports: list[dict[str, Any]]) -> None:
    """Print the full report list table."""
    console.print(_build_report_table(reports, title="Report List"))


def render_menu() -> None:
    """Display the Reports Center menu inside a Rich Panel."""
    menu_text = (
        "[bold cyan]1.[/bold cyan] View Report\n"
        "[bold cyan]2.[/bold cyan] Search Report\n"
        "[bold cyan]3.[/bold cyan] Delete Report\n"
        "[bold cyan]4.[/bold cyan] Report Information\n"
        "[bold cyan]5.[/bold cyan] Refresh\n"
        "[bold cyan]0.[/bold cyan] Back"
    )
    console.print(Panel(menu_text, title="[bold white]MENU[/bold white]", border_style="bright_blue", expand=False))


def _pause() -> None:
    """Shared 'press Enter to continue' pause, safe in non-interactive contexts."""
    try:
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="", show_default=False)
    except (EOFError, KeyboardInterrupt):
        pass


# ==============================================================================
# VIEW REPORT
# ==============================================================================
def _read_report_content(path: str) -> tuple[Optional[str], Optional[str]]:
    """
    Safely read a report's content for display.

    Returns:
        (content, error). Exactly one of the two is None: on success,
        error is None and content holds the (possibly truncated/pretty-
        printed) text; on failure, content is None and error explains why.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return None, f"Could not access file: {exc}"

    truncated_notice = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as report_file:
            if size > MAX_VIEW_BYTES:
                content = report_file.read(MAX_VIEW_BYTES)
                truncated_notice = (
                    f"\n\n[dim]--- Truncated: file is {_human_readable_size(size)}, "
                    f"showing the first {_human_readable_size(MAX_VIEW_BYTES)} ---[/dim]"
                )
            else:
                content = report_file.read()
    except OSError as exc:
        return None, f"Could not read file: {exc}"

    # Pretty-print JSON content for readability; if it doesn't parse (e.g.
    # truncated mid-structure, or simply not valid JSON), fall back to
    # showing it as-is rather than failing the whole view.
    if path.lower().endswith(".json"):
        try:
            import json
            parsed = json.loads(content)
            content = json.dumps(parsed, indent=4, ensure_ascii=False)
        except Exception:
            pass

    return content + truncated_notice, None


def _paginate_content(content: str, title: str) -> None:
    """
    Print `content` page by page (LINES_PER_PAGE lines at a time), letting
    the analyst press Enter to advance or 'q' to stop early. Guarantees at
    least one page is shown even for empty content.
    """
    lines = content.splitlines() or [""]
    total_lines = len(lines)
    total_pages = max(1, math.ceil(total_lines / LINES_PER_PAGE))

    page = 0
    while page < total_pages:
        start = page * LINES_PER_PAGE
        end = start + LINES_PER_PAGE
        page_text = "\n".join(lines[start:end])

        clear_terminal()
        console.print(
            Panel(
                page_text,
                title=f"[bold cyan]{title}[/bold cyan] (Page {page + 1}/{total_pages})",
                border_style="cyan",
            )
        )

        if page + 1 >= total_pages:
            console.print("[dim]-- End of report --[/dim]")
            break

        try:
            choice = Prompt.ask(
                "\n[bold green]Enter[/bold green] for next page, or [bold green]q[/bold green] to stop",
                default="",
                show_default=False,
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice in ("q", "quit", "exit"):
            break

        page += 1


def render_view_report(reports: list[dict[str, Any]]) -> None:
    """Prompt for a report ID and display its content, paginated if large."""
    if not reports:
        console.print(Panel("[yellow]No reports available to view.[/yellow]", border_style="yellow"))
        return

    raw_id = Prompt.ask("[bold cyan]Enter Report ID to view[/bold cyan]").strip()
    entry = _find_report_by_id(reports, raw_id)
    if entry is None:
        console.print(Panel(f"[bold red]No report found with ID '{raw_id}'.[/bold red]", border_style="red"))
        return

    content, error = _read_report_content(entry["path"])
    if error is not None:
        console.print(Panel(f"[bold red]{error}[/bold red]", title=entry["name"], border_style="red"))
        return

    if not content.strip():
        console.print(Panel("[dim]This report is empty.[/dim]", title=entry["name"], border_style="cyan"))
        return

    _paginate_content(content, entry["name"])


# ==============================================================================
# SEARCH REPORT
# ==============================================================================
def render_search_report(reports: list[dict[str, Any]]) -> None:
    """Prompt for a filename keyword and display matching reports."""
    if not reports:
        console.print(Panel("[yellow]No reports available to search.[/yellow]", border_style="yellow"))
        return

    keyword = Prompt.ask("[bold cyan]Enter filename keyword to search[/bold cyan]").strip()
    if not keyword:
        console.print(Panel("[yellow]No keyword entered.[/yellow]", border_style="yellow"))
        return

    matches = [entry for entry in reports if keyword.lower() in entry["name"].lower()]
    console.print(_build_report_table(matches, title=f"Search Results: '{keyword}'"))


# ==============================================================================
# DELETE REPORT
# ==============================================================================
def render_delete_report(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Prompt for a report ID, confirm, and delete it if confirmed.

    Returns:
        list[dict]: the (possibly refreshed) reports list - refreshed from
        disk after a successful delete, unchanged otherwise.
    """
    if not reports:
        console.print(Panel("[yellow]No reports available to delete.[/yellow]", border_style="yellow"))
        return reports

    raw_id = Prompt.ask("[bold cyan]Enter Report ID to delete[/bold cyan]").strip()
    entry = _find_report_by_id(reports, raw_id)
    if entry is None:
        console.print(Panel(f"[bold red]No report found with ID '{raw_id}'.[/bold red]", border_style="red"))
        return reports

    try:
        confirmed = Confirm.ask(
            f"[bold red]Permanently delete '{entry['name']}'? This cannot be undone.[/bold red]",
            default=False,
        )
    except (EOFError, KeyboardInterrupt):
        confirmed = False

    if not confirmed:
        console.print(Panel("[yellow]Deletion cancelled.[/yellow]", border_style="yellow"))
        return reports

    try:
        os.remove(entry["path"])
        console.print(Panel(f"[bold green]Report '{entry['name']}' deleted successfully.[/bold green]", border_style="green"))
        return get_reports()
    except OSError as exc:
        console.print(Panel(f"[bold red]Failed to delete report: {exc}[/bold red]", border_style="red"))
        return reports


# ==============================================================================
# REPORT INFORMATION
# ==============================================================================
def render_report_info(reports: list[dict[str, Any]]) -> None:
    """Prompt for a report ID and display its full file metadata."""
    if not reports:
        console.print(Panel("[yellow]No reports available.[/yellow]", border_style="yellow"))
        return

    raw_id = Prompt.ask("[bold cyan]Enter Report ID for details[/bold cyan]").strip()
    entry = _find_report_by_id(reports, raw_id)
    if entry is None:
        console.print(Panel(f"[bold red]No report found with ID '{raw_id}'.[/bold red]", border_style="red"))
        return

    _, ext = os.path.splitext(entry["name"])

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="bold white")
    table.add_column("Value", style="cyan")
    table.add_row("Full Path", os.path.abspath(entry["path"]))
    table.add_row("Created Date", _format_timestamp(entry["created"]))
    table.add_row("Modified Date", _format_timestamp(entry["modified"]))
    table.add_row("File Size", _human_readable_size(entry["size"]))
    table.add_row("Extension", ext if ext else "(none)")

    console.print(
        Panel(table, title=f"[bold cyan]REPORT INFORMATION - {entry['name']}[/bold cyan]", border_style="cyan")
    )


# ==============================================================================
# ENTRY POINT
# ==============================================================================
def run() -> None:
    """
    Entry point for the Reports Center.

    Scans reports/ and loops: render the current list + menu, dispatch the
    chosen action, then re-render. Returns to the caller (m0x1.py) when the
    user selects '0'. Guaranteed not to crash - every render and every
    filesystem operation is defensively wrapped, and the outer loop itself
    is guarded so an unexpected error prints a message and returns safely
    instead of taking down the whole platform.
    """
    reports = get_reports()

    while True:
        try:
            clear_terminal()
            _render_section(render_title, "Title")
            console.print(Rule(style="bright_blue"))

            _render_section(lambda: render_summary(reports), "Summary")
            _render_section(lambda: render_report_list(reports), "Report List")

            console.print(Rule(style="bright_blue"))
            _render_section(render_menu, "Menu")

            choice = Prompt.ask(
                "[bold green]Select an option[/bold green]",
                choices=["0", "1", "2", "3", "4", "5"],
                show_choices=False,
            )

            if choice == "1":
                _render_section(lambda: render_view_report(reports), "View Report")
                _pause()
            elif choice == "2":
                _render_section(lambda: render_search_report(reports), "Search Report")
                _pause()
            elif choice == "3":
                try:
                    reports = render_delete_report(reports)
                except Exception as exc:  # noqa: BLE001
                    console.print(Panel(f"[bold red]Unexpected error deleting report: {exc}[/bold red]", border_style="red"))
                _pause()
            elif choice == "4":
                _render_section(lambda: render_report_info(reports), "Report Information")
                _pause()
            elif choice == "5":
                reports = get_reports()
                console.print(Panel("[bold green]Reports directory refreshed.[/bold green]", border_style="green"))
                _pause()
            elif choice == "0":
                console.print("[bold yellow]Returning to main menu...[/bold yellow]")
                break

        except KeyboardInterrupt:
            console.print("\n[bold red]Operation interrupted by user (Ctrl+C).[/bold red]")
            break
        except EOFError:
            # Non-interactive environment with no more input - exit quietly.
            break
        except Exception as exc:  # noqa: BLE001 - top-level safety net for the module
            console.print(
                Panel(
                    f"[bold red]Unexpected error in Reports Center: {exc}[/bold red]",
                    border_style="red",
                )
            )
            break


if __name__ == "__main__":
    run()