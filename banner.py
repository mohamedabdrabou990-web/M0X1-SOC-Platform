from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.progress import Progress
import time
import os

from utils import system
import config

console = Console()


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def show_banner():

    clear()

    logo = r"""
███╗   ███╗ ██████╗ ██╗  ██╗ ██╗
████╗ ████║██╔═████╗╚██╗██╔╝███║
██╔████╔██║██║██╔██║ ╚███╔╝ ╚██║
██║╚██╔╝██║████╔╝██║ ██╔██╗  ██║
██║ ╚═╝ ██║╚██████╔╝██╔╝ ██╗ ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═╝
"""

    left = Panel.fit(
        logo,
        title=config.APP_NAME,
        border_style="cyan"
    )

    right = Panel.fit(
f"""[cyan]User[/cyan]      : {system.get_username()}
[cyan]Host[/cyan]      : {system.get_hostname()}
[cyan]OS[/cyan]        : {system.get_os()}
[cyan]Python[/cyan]    : {system.get_python_version()}
[cyan]Version[/cyan]   : {config.VERSION}
[cyan]Time[/cyan]      : {system.get_current_time()}
""",
        title="System",
        border_style="green"
    )

    console.print(Columns([left, right]))


def loading():

    with Progress() as progress:

        task = progress.add_task("[green]Loading Modules...", total=100)

        while not progress.finished:

            progress.update(task, advance=2)

            time.sleep(0.02)

    console.print("[bold green][✓] System Ready[/bold green]")

    time.sleep(0.8)