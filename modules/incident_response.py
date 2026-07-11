
import os
import sys
import json
import shutil
import signal
import platform
import subprocess
import re  # تم إضافة مكتبة الـ Regex لاستخراج الـ IP والبيانات المدمجة
from datetime import datetime

# Rich UI Component Imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

# Configuration Paths
ALERTS_PATH = "reports/alerts.json"
HISTORY_PATH = "reports/incident_history.json"
INCIDENTS_DIR = "reports/incidents/"
QUARANTINE_DIR = "quarantine/"

console = Console()

# --- Helper Functions ---

def load_json_file(file_path: str, default_factory=list):
    if not os.path.exists(file_path):
        return default_factory()
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, PermissionError):
        console.print(f"[bold red]Error:[/bold red] Failed to parse or access {file_path}.")
        return default_factory()

def save_json_file(file_path: str, data) -> bool:
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        console.print(f"[bold red]Storage Error:[/bold red] Could not write to {file_path}. Details: {e}")
        return False

def log_incident_history(incident_id: str, action: str, note: str = ""):
    history = load_json_file(HISTORY_PATH, list)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "incident_id": str(incident_id),
        "action": action,
        "analyst_note": note
    }
    history.append(entry)
    save_json_file(HISTORY_PATH, history)

def get_severity_style(severity: str) -> str:
    sev = severity.lower()
    if "critical" in sev: return "bold red"
    if "high" in sev: return "red"
    if "medium" in sev: return "yellow"
    return "green"

def get_status_style(status: str) -> str:
    stat = status.lower()
    if "resolved" in stat: return "bold green"
    if "investigating" in stat: return "bold yellow"
    return "bold cyan"

# --- Regex Dynamic Extractors ---

def extract_ip(alert: dict) -> str:
    """يستخرج الآي بي سواء كان كمفتاح منفصل أو مدمج داخل الوصف"""
    if alert.get("ip_address"):
        return alert["ip_address"]
    
    # البحث عن نمط IPv4 داخل الوصف
    description = alert.get("description", "")
    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', description)
    if ip_match:
        return ip_match.group(0)
    return ""

def extract_pid(alert: dict) -> str:
    """يستخرج الـ PID إذا كان موجود كـ Key أو يبحث عنه في الوصف"""
    if alert.get("pid"):
        return str(alert["pid"])
    
    description = alert.get("description", "")
    pid_match = re.search(r'\b(?:PID|pid|Process|process|ID)\s*[:=]?\s*([0-9]+)\b', description)
    if pid_match:
        return pid_match.group(1)
    return ""

def extract_file_path(alert: dict) -> str:
    """يستخرج مسار الملف إذا كان موجود كـ Key أو يبحث عن أنماط مسارات في الوصف"""
    if alert.get("file_path"):
        return alert["file_path"]
    
    description = alert.get("description", "")
    # نمط بسيط للبحث عن مسارات الملفات المذكورة في الوصف
    path_match = re.search(r'(?:/[a-zA-Z0-9_\.\-]+)+|[a-zA-Z]:\\[a-zA-Z0-9_\.\-\\]+', description)
    if path_match:
        return path_match.group(0)
    return ""

# --- Core Logic Actions ---

def quarantine_file(alert: dict) -> str:
    file_path = extract_file_path(alert)
    if not file_path:
        return "Failed: No file path found or extracted from alert metadata."
    if not os.path.exists(file_path):
        return f"Failed: Targeted file system path does not exist: {file_path}"
    
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        base_name = os.path.basename(file_path)
        destination = os.path.join(QUARANTINE_DIR, f"{base_name}.quarantine")
        shutil.move(file_path, destination)
        return f"Success: Moved {file_path} to safe zone: {destination}"
    except PermissionError:
        return f"Failed: Insufficient system privileges to move file: {file_path}"
    except Exception as e:
        return f"Failed to quarantine due to error: {str(e)}"

def kill_process(alert: dict) -> str:
    pid = extract_pid(alert)
    if not pid:
        return "Failed: No target Process ID (PID) found or extracted from alert description."
    try:
        target_pid = int(pid)
        os.kill(target_pid, signal.SIGTERM)
        return f"Success: Dispatched SIGTERM to active Process ID {target_pid}"
    except ProcessLookupError:
        return f"Failed: Process ID {pid} is no longer running on the host system."
    except PermissionError:
        return f"Failed: Root/Administrator context required to terminate PID {pid}."
    except Exception as e:
        return f"Failed: Error encountered stopping process execution: {str(e)}"

def block_ip_address(alert: dict) -> str:
    ip = extract_ip(alert)
    if not ip:
        return "Failed: No target IP network address could be found or extracted from this alert."
    
    current_os = platform.system()
    if current_os == "Windows":
        return f"Skipped: Windows Firewall block automation is unsupported (Extracted IP: {ip})."
    
    if current_os == "Linux":
        if shutil.which("iptables"):
            try:
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return f"Success: Blocked target IP {ip} via iptables configuration."
            except subprocess.CalledProcessError as e:
                return f"Failed: Privilege escalation issues via iptables: {e.stderr.decode().strip()}"
        
        elif shutil.which("nft"):
            try:
                cmd = ["sudo", "nft", "add", "rule", "inet", "filter", "input", f"ip saddr {ip} drop"]
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return f"Success: Blocked target IP {ip} via nftables configuration."
            except subprocess.CalledProcessError as e:
                return f"Failed: Inability to execute changes via nftables: {e.stderr.decode().strip()}"
        
        return f"Failed: Neither iptables nor nftables utilities were detected (Extracted IP: {ip})."
        
    return f"Skipped: Unsupported platform {current_os} (Extracted IP: {ip})."

def export_incident_report(alert: dict) -> str:
    report_filename = f"incident_{alert['id']}.json"
    target_path = os.path.join(INCIDENTS_DIR, report_filename)
    
    report_data = {
        "incident_id": alert["id"],
        "export_timestamp": datetime.now().isoformat(),
        "resolution_status": alert.get("status", "New"),
        "resolution_timestamp": alert.get("resolution_timestamp", "N/A"),
        "extracted_indicators": {
            "extracted_ip": extract_ip(alert),
            "extracted_pid": extract_pid(alert),
            "extracted_file": extract_file_path(alert)
        },
        "analyst_notes": alert.get("notes", []),
        "actions_taken": alert.get("actions_taken", []),
        "underlying_alert_payload": alert
    }
    
    if save_json_file(target_path, report_data):
        return f"Success: Saved incident report to {target_path}"
    return "Failed: Error committing report to disk."

# --- Views & Interface Interfaces ---

def display_dashboard(alerts: list):
    table = Table(title="M0X1 Incident Response Tracking Dashboard", expand=True)
    table.add_column("Alert ID", justify="center", style="cyan", no_wrap=True)
    table.add_column("Date/Time", justify="left")
    table.add_column("Severity", justify="center")
    table.add_column("Alert Type", justify="left", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Description Context", justify="left")

    for alert in alerts:
        table.add_row(
            str(alert.get("id")),
            alert.get("timestamp", "Unknown"),
            f"[{get_severity_style(alert.get('severity', 'Low'))}]{alert.get('severity')}[/]",
            alert.get("alert_type", "Generic Event"),
            f"[{get_status_style(alert.get('status', 'New'))}]{alert.get('status', 'New')}[/]",
            alert.get("description", "N/A")
        )
    console.print(table)

def display_incident_details(alert: dict):
    # استخراج البيانات ديناميكياً للعرض في الـ Panel
    ext_ip = extract_ip(alert) or "Not Found Contextually"
    ext_pid = extract_pid(alert) or "Not Found Contextually"
    ext_file = extract_file_path(alert) or "Not Found Contextually"

    details_text = Text()
    details_text.append(f"Alert ID: ", style="bold")
    details_text.append(f"{alert.get('id')}\n", style="cyan")
    details_text.append(f"Timestamp: ", style="bold")
    details_text.append(f"{alert.get('timestamp')}\n")
    details_text.append(f"Severity: ", style="bold")
    details_text.append(f"{alert.get('severity')}\n", style=get_severity_style(alert.get('severity', 'Low')))
    details_text.append(f"Type: ", style="bold")
    details_text.append(f"{alert.get('alert_type')}\n", style="magenta")
    details_text.append(f"Current Status: ", style="bold")
    details_text.append(f"{alert.get('status', 'New')}\n", style=get_status_style(alert.get('status', 'New')))
    details_text.append(f"Description: ", style="bold")
    details_text.append(f"{alert.get('description', 'N/A')}\n\n")

    details_text.append("--- Extracted Payload Indicators (Dynamic Parse) ---\n", style="bold blue")
    details_text.append(f"Target File Location: {ext_file}\n")
    details_text.append(f"Active Process ID (PID): {ext_pid}\n")
    details_text.append(f"Hostile Network Source IP: {ext_ip}\n\n")

    details_text.append("--- Analyst Evaluation Notes ---\n", style="bold yellow")
    notes = alert.get("notes", [])
    if notes:
        for idx, note in enumerate(notes, 1):
            details_text.append(f"[{idx}] {note}\n")
    else:
        details_text.append("No investigative logging entries recorded.\n", style="italic dim")

    details_text.append("\n--- History Matrix Tracking ---\n", style="bold green")
    actions = alert.get("actions_taken", [])
    if actions:
        for action in actions:
            details_text.append(f"• {action}\n")
    else:
        details_text.append("No containment operations executed yet.\n", style="italic dim")

    panel = Panel(details_text, title=f"Detailed Inspection Framework — Alert ID #{alert['id']}", expand=True)
    console.print(panel)

def capture_multiline_notes() -> str:
    console.print("[yellow]Enter notes (Press Enter on an empty line to save):[/yellow]")
    lines = []
    while True:
        try:
            line = input()
            if not line.strip() and lines:
                break
            if not line.strip() and not lines:
                console.print("[dim italic]Empty note ignored. Returning...[/dim italic]")
                return ""
            lines.append(line)
        except EOFError:
            break
    return "\n".join(lines)

def handle_incident_actions(alert: dict, alerts_list: list):
    while True:
        console.clear()
        display_incident_details(alert)
        
        console.print("\n[bold cyan]Available Response Remediation Options:[/bold cyan]")
        console.print("[1] Mark Status as Investigating")
        console.print("[2] Mark Status as Resolved")
        console.print("[3] Add Case Analyst Journal Notes")
        console.print("[4] Isolate and Quarantine Targeted File")
        console.print("[5] Kill Active Process ID (PID)")
        console.print("[6] Block Hostile Source IP Address via Firewall")
        console.print("[7] Export Complete Incident Report (JSON)")
        console.print("[8] Return to Main Queue Dashboard")
        
        choice = Prompt.ask("\nSelect action vector", choices=["1", "2", "3", "4", "5", "6", "7", "8"], default="8")
        
        if "notes" not in alert: alert["notes"] = []
        if "actions_taken" not in alert: alert["actions_taken"] = []

        if choice == "1":
            alert["status"] = "Investigating"
            log_incident_history(alert["id"], "Incident Investigating")
            alert["actions_taken"].append(f"[{datetime.now().isoformat()}] Status changed to Investigating.")
            console.print("[bold green]Success:[/bold green] Incident marked as Investigating.")
            
        elif choice == "2":
            alert["status"] = "Resolved"
            alert["resolution_timestamp"] = datetime.now().isoformat()
            log_incident_history(alert["id"], "Incident Resolved")
            alert["actions_taken"].append(f"[{datetime.now().isoformat()}] Status changed to Resolved.")
            console.print("[bold green]Success:[/bold green] Incident marked as Resolved.")
            
        elif choice == "3":
            new_note = capture_multiline_notes()
            if new_note:
                alert["notes"].append(f"[{datetime.now().isoformat()}] {new_note}")
                log_incident_history(alert["id"], "Added Analyst Notes", new_note)
                console.print("[bold green]Success:[/bold green] Note appended.")
                
        elif choice in ["4", "5", "6", "7"]:
            action_desc = ""
            result_msg = ""
            
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                if choice == "4":
                    progress.add_task(description="Quarantining file...", total=None)
                    result_msg = quarantine_file(alert)
                    action_desc = "File Quarantined"
                elif choice == "5":
                    progress.add_task(description="Terminating active process...", total=None)
                    result_msg = kill_process(alert)
                    action_desc = "Process Terminated"
                elif choice == "6":
                    progress.add_task(description="Configuring firewall block rules...", total=None)
                    result_msg = block_ip_address(alert)
                    action_desc = "IP Blocked"
                elif choice == "7":
                    progress.add_task(description="Compiling report...", total=None)
                    result_msg = export_incident_report(alert)
                    action_desc = "Incident Report Exported"

            if "Success" in result_msg:
                console.print(f"[bold green]{result_msg}[/bold green]")
                alert["actions_taken"].append(f"[{datetime.now().isoformat()}] {action_desc} - {result_msg}")
                log_incident_history(alert["id"], action_desc, result_msg)
            else:
                console.print(f"[bold red]{result_msg}[/bold red]")
                
        elif choice == "8":
            save_json_file(ALERTS_PATH, alerts_list)
            break
            
        Prompt.ask("\nPress [bold]Enter[/bold] to continue...")

def start_module():
    while True:
        console.clear()
        
        if not os.path.exists(ALERTS_PATH):
            console.print(Panel(
                f"[bold yellow]Alert Log Source Data Missing:[/bold yellow]\n"
                f"The log file '{ALERTS_PATH}' could not be located.",
                title="M0X1 SOC Error", border_style="red"
            ))
            Prompt.ask("\nPress [bold]Enter[/bold] to exit")
            return

        alerts = load_json_file(ALERTS_PATH, list)
        if not alerts:
            console.print("[bold yellow]Queue Status Clear:[/bold yellow] No active alerts available.\n")
            Prompt.ask("Press [bold]Enter[/bold] to return")
            return

        display_dashboard(alerts)
        selection = Prompt.ask("\nEnter an [bold cyan]Alert ID[/bold cyan] to triage (or type [bold red]'q'[/bold red] to return)")
        
        if selection.lower() == 'q':
            break
            
        matched_alert = next((item for item in alerts if str(item.get("id")) == selection.strip()), None)
        if matched_alert:
            handle_incident_actions(matched_alert, alerts)
        else:
            console.print(f"[bold red]Error:[/bold red] Identifier '{selection}' was not found.")
            Prompt.ask("\nPress [bold]Enter[/bold] to retry...")

def run():
    start_module()

if __name__ == "__main__":
    try:
        start_module()
    except KeyboardInterrupt:
        sys.exit(0)