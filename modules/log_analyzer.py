import os
import re
from rich.console import Console
from rich.table import Table

console = Console()


def run():
    console.clear()

    console.rule("[bold cyan]Log Analyzer[/bold cyan]")

    path = input("\nEnter log file path: ").strip()

    if not os.path.isfile(path):
        console.print("\n[red]File not found![/red]")
        input("\nPress Enter to continue...")
        return

    with open(path, "r", errors="ignore") as f:
        lines = f.readlines()

    total = len(lines)

    errors = 0
    warnings = 0
    failed_login = 0
    ip_counter = {}

    ip_regex = r"(?:\d{1,3}\.){3}\d{1,3}"

    for line in lines:

        lower = line.lower()

        if "error" in lower:
            errors += 1

        if "warning" in lower or "warn" in lower:
            warnings += 1

        if "failed" in lower or "login failed" in lower or "authentication failure" in lower:
            failed_login += 1

        ips = re.findall(ip_regex, line)

        for ip in ips:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

    table = Table(title="Log Analysis Report")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Lines", str(total))
    table.add_row("Errors", str(errors))
    table.add_row("Warnings", str(warnings))
    table.add_row("Failed Logins", str(failed_login))
    table.add_row("Unique IPs", str(len(ip_counter)))

    console.print(table)

    if ip_counter:

        console.print("\n[bold yellow]Top IP Addresses[/bold yellow]")

        ip_table = Table()

        ip_table.add_column("IP")
        ip_table.add_column("Count")

        top_ips = sorted(
            ip_counter.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        for ip, count in top_ips:
            ip_table.add_row(ip, str(count))

        console.print(ip_table)

    console.print("\n[green]Analysis Completed Successfully.[/green]")

    input("\nPress Enter to continue...")