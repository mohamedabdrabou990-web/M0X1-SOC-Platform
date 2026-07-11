from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def header(module_name: str):
    """يعرض عنوان الصفحة الحالية"""
    console.print()
    console.rule(f"[bold cyan]{module_name}")
    console.print()


def footer():
    """يعرض الفوتر الثابت"""
    console.print()
    console.rule(style="cyan")
    console.print(
        "[bold green]Status:[/bold green] READY    |    "
        "[yellow]Press 0 to return to Main Menu[/yellow]"
    )
    console.print()


def success(message: str):
    console.print(f"[bold green][+][/bold green] {message}")


def error(message: str):
    console.print(f"[bold red][-][/bold red] {message}")


def warning(message: str):
    console.print(f"[bold yellow][!][/bold yellow] {message}")


def info(message: str):
    console.print(f"[bold cyan][*][/bold cyan] {message}")


def pause():
    input("\nPress Enter to continue...")