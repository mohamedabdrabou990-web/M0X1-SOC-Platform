
import psutil
from rich.console import Console
from rich.table import Table

console = Console()


def run():
    """
    Display running processes.
    """

    table = Table(
        title="Running Processes",
        show_lines=False,
        header_style="bold cyan"
    )

    table.add_column("PID", justify="right")
    table.add_column("Name", style="green")
    table.add_column("User", style="yellow")
    table.add_column("CPU %", justify="right")
    table.add_column("RAM %", justify="right")
    table.add_column("Status", style="magenta")

    processes = []

    for proc in psutil.process_iter([
        "pid",
        "name",
        "username",
        "cpu_percent",
        "memory_percent",
        "status"
    ]):
        try:
            info = proc.info
            processes.append(info)
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    processes = sorted(
        processes,
        key=lambda p: p["memory_percent"],
        reverse=True
    )

    for proc in processes:

        cpu = proc["cpu_percent"] or 0
        ram = proc["memory_percent"] or 0

        table.add_row(
            str(proc["pid"]),
            str(proc["name"]),
            str(proc["username"]),
            f"{cpu:.1f}",
            f"{ram:.1f}",
            str(proc["status"])
        )

    console.print(table)

    console.print(
        f"\n[bold green]Total Processes:[/bold green] {len(processes)}"
    )

    input("\nPress Enter to return...")