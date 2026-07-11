from rich.console import Console
from rich.table import Table

console = Console()


def show_menu():
    table = Table(title="M0X1 SOC MENU")

    table.add_column("Option", style="cyan", justify="center")
    table.add_column("Module", style="green")

    table.add_row("1", "Network Scanner")
    table.add_row("2", "Process Monitor")
    table.add_row("3", "Log Analyzer")
    table.add_row("4", "IOC Scanner")
    table.add_row("5", "Alert Manager")
    table.add_row("6", "Threat Intelligence")
    table.add_row("7", "Live Monitoring")
    table.add_row("8", "Dashboard")
    table.add_row("9", "Reports")
    table.add_row("10", "Incident Response")
    table.add_row("0", "Exit")

    console.print(table)

    return input("\nSelect Option > ")