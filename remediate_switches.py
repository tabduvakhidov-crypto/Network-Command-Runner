#!/usr/bin/env python3
"""
Switch Vulnerability Remediation Tool (CLI)
Automates disabling SSH v1 across multiple switches with credential fallback,
multi-threaded execution, and audit reporting.
"""

import os
import sys
import json
import logging
import argparse
from typing import List, Dict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm

# Import core engine
from remediation_engine import (
    extract_valid_ips,
    remediate_batch,
    save_audit_reports,
    RemediationResult,
)

console = Console()

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
DEFAULT_CREDS_PATH = os.path.join(os.path.dirname(__file__), "credentials.json")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


def setup_logger() -> logging.Logger:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    log_file = os.path.join(REPORTS_DIR, "remediation_execution.log")
    logger = logging.getLogger("SwitchRemediation")
    logger.setLevel(logging.INFO)

    # File handler
    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger


def load_config() -> Dict:
    if os.path.exists(DEFAULT_CONFIG_PATH):
        try:
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not read config.json ({e}). Using defaults.[/yellow]")
    return {
        "device_type": "cisco_ios",
        "commands": ["ip ssh version 2"],
        "save_config": True,
        "save_command": "write memory",
        "max_workers": 10,
        "connect_timeout": 15,
        "banner_timeout": 15,
        "auth_timeout": 15,
        "global_delay_factor": 1.0,
        "preflight_port_check": True,
    }


def load_credentials() -> List[Dict]:
    if not os.path.exists(DEFAULT_CREDS_PATH):
        return []
    try:
        with open(DEFAULT_CREDS_PATH, "r", encoding="utf-8") as f:
            creds = json.load(f)
            return creds if isinstance(creds, list) else []
    except Exception as e:
        console.print(f"[red]Error loading credentials.json: {e}[/red]")
        return []


def check_and_prompt_credentials(creds: List[Dict]) -> List[Dict]:
    """Ensures there are valid credentials before execution."""
    has_placeholder = any(
        "CHANGEME" in c.get("password", "") or "CHANGEME" in c.get("username", "")
        for c in creds
    )

    if not creds or has_placeholder:
        console.print(
            Panel(
                "[bold yellow]Credential Configuration Notice[/bold yellow]\n\n"
                "Credentials in [cyan]credentials.json[/cyan] appear to be missing or using placeholders ('CHANGEME').\n"
                "You can either edit [cyan]credentials.json[/cyan] or enter a credential profile right now.",
                border_style="yellow",
            )
        )
        choice = Prompt.ask(
            "Do you want to enter a credential set now?",
            choices=["y", "n"],
            default="y",
        )
        if choice == "y":
            username = Prompt.ask("Enter Username")
            password = Prompt.ask("Enter Password", password=True)
            secret = Prompt.ask("Enter Enable Secret (optional, press Enter to use password)", password=True)
            new_cred = {
                "name": "Interactive Credential",
                "username": username,
                "password": password,
                "secret": secret if secret else password,
            }
            # Append or replace placeholder
            creds = [c for c in creds if "CHANGEME" not in c.get("password", "")]
            creds.insert(0, new_cred)
            # Ask if user wants to save
            if Confirm.ask("Save this credential set to credentials.json for future runs?"):
                with open(DEFAULT_CREDS_PATH, "w", encoding="utf-8") as f:
                    json.dump(creds, f, indent=2)
                console.print("[green]Saved to credentials.json.[/green]")
    return creds


def prompt_for_ips() -> List[str]:
    """Interactive multi-line prompt allowing direct paste of IP addresses."""
    console.print(
        Panel(
            "[bold cyan]Paste IP Addresses[/bold cyan]\n"
            "Paste your switch IP addresses below (from Excel, text file, inventory, etc.).\n"
            "You can paste multiple lines or comma-separated addresses.\n"
            "[italic dim]When finished, press Enter on an empty line or type 'done'.[/italic dim]",
            border_style="cyan",
        )
    )

    lines = []
    while True:
        try:
            line = input()
            if line.strip().lower() == "done" or (not line.strip() and lines):
                break
            if line.strip():
                lines.append(line)
        except (EOFError, KeyboardInterrupt):
            break

    raw_text = "\n".join(lines)
    ips = extract_valid_ips(raw_text)
    return ips


def display_summary_table(results: List[RemediationResult]):
    """Renders a styled summary table of the remediation execution."""
    table = Table(title="Switch Remediation Results Summary", border_style="dim")
    table.add_column("IP Address", style="bold cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Credential Used", style="green")
    table.add_column("Duration", justify="right")
    table.add_column("Details", style="dim")

    success_count = 0
    auth_fail_count = 0
    unreach_count = 0
    error_count = 0

    for r in results:
        if r.status == "SUCCESS":
            status_style = "[bold green]SUCCESS[/bold green]"
            success_count += 1
            details = "SSH v1 disabled & config saved"
        elif r.status == "AUTH_FAILED":
            status_style = "[bold red]AUTH FAILED[/bold red]"
            auth_fail_count += 1
            details = r.error_message
        elif r.status == "UNREACHABLE":
            status_style = "[bold yellow]UNREACHABLE[/bold yellow]"
            unreach_count += 1
            details = r.error_message
        else:
            status_style = "[bold magenta]ERROR[/bold magenta]"
            error_count += 1
            details = r.error_message

        table.add_row(
            r.ip,
            status_style,
            r.credential_used or "-",
            f"{r.duration_seconds}s",
            details[:60] + ("..." if len(details) > 60 else ""),
        )

    console.print("\n")
    console.print(table)

    # Overview panel
    summary_text = (
        f"[bold]Total Switches:[/bold] {len(results)}  |  "
        f"[bold green]Succeeded:[/bold green] {success_count}  |  "
        f"[bold red]Auth Failed:[/bold red] {auth_fail_count}  |  "
        f"[bold yellow]Unreachable:[/bold yellow] {unreach_count}  |  "
        f"[bold magenta]Errors:[/bold magenta] {error_count}"
    )
    console.print(Panel(summary_text, title="Execution Summary", border_style="blue"))


def main():
    parser = argparse.ArgumentParser(
        description="Automated Switch Vulnerability Remediation (Disables SSH v1 with Credential Fallback)"
    )
    parser.add_argument(
        "--file", "-f", help="Path to text file containing switch IP addresses"
    )
    parser.add_argument(
        "--workers", "-w", type=int, help="Number of concurrent worker threads"
    )
    parser.add_argument(
        "--command", "-c", action="append", help="Custom command to run (can specify multiple)"
    )
    parser.add_argument(
        "--no-save", action="store_true", help="Do not save running configuration"
    )
    args = parser.parse_args()

    console.print(
        Panel.fit(
            "[bold white]SWITCH VULNERABILITY REMEDIATION TOOL[/bold white]\n"
            "[dim]Disable SSH v1 & Enforce SSH v2 across Network Fleet[/dim]\n"
            "[green]Features: Credential Fallback • Multi-Threading • Audit Logging[/green]",
            border_style="bright_blue",
        )
    )

    # 1. Load Config
    config = load_config()
    if args.workers:
        config["max_workers"] = args.workers
    if args.command:
        config["commands"] = args.command
    if args.no_save:
        config["save_config"] = False

    # 2. Load & Validate Credentials
    creds = load_credentials()
    creds = check_and_prompt_credentials(creds)
    if not creds:
        console.print("[red]No credentials configured! Please edit credentials.json or run again.[/red]")
        sys.exit(1)

    # 3. Get IP Addresses
    ips = []
    if args.file:
        if not os.path.exists(args.file):
            console.print(f"[red]Error: IP file '{args.file}' does not exist![/red]")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            ips = extract_valid_ips(f.read())
    else:
        ips = prompt_for_ips()

    if not ips:
        console.print("[yellow]No valid IP addresses provided. Exiting.[/yellow]")
        sys.exit(0)

    console.print(f"\n[green]Loaded {len(ips)} valid unique switch IP(s).[/green]")

    # 4. Confirm Plan
    commands_str = "\n".join(f"  • {cmd}" for cmd in config.get("commands", []))
    save_str = "Yes (" + config.get("save_command", "write memory") + ")" if config.get("save_config") else "No"
    cred_names = ", ".join(c.get("name", c.get("username", "Unnamed")) for c in creds)

    plan_table = Table.grid(padding=(0, 2))
    plan_table.add_column(style="bold")
    plan_table.add_column()
    plan_table.add_row("Device Type:", config.get("device_type", "cisco_ios"))
    plan_table.add_row("Commands to Run:", commands_str.strip())
    plan_table.add_row("Save Config:", save_str)
    plan_table.add_row("Credentials to Try:", cred_names)
    plan_table.add_row("Parallel Threads:", str(config.get("max_workers", 10)))

    console.print(Panel(plan_table, title="[bold]Remediation Execution Plan[/bold]", border_style="cyan"))

    if not Confirm.ask("Proceed with execution on these switches?", default=True):
        console.print("[yellow]Execution cancelled by user.[/yellow]")
        sys.exit(0)

    # 5. Execute with Progress Bar
    logger = setup_logger()
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total} switches)"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Remediating switches...", total=len(ips))

        def on_progress(completed: int, total: int, last_res: RemediationResult):
            progress.update(task, completed=completed)

        results = remediate_batch(
            ips=ips,
            credentials=creds,
            commands=config.get("commands", []),
            config=config,
            progress_callback=on_progress,
            logger=logger,
        )

    # 6. Display Results Table
    display_summary_table(results)

    # 7. Save Reports
    csv_path, log_dir = save_audit_reports(results, output_dir=REPORTS_DIR)
    console.print(
        Panel(
            f"[bold green]Audit Reports Successfully Saved:[/bold green]\n"
            f"  • Summary CSV: [cyan]{csv_path}[/cyan]\n"
            f"  • Device Logs: [cyan]{log_dir}[/cyan]\n"
            f"  • Execution Log: [cyan]{os.path.join(REPORTS_DIR, 'remediation_execution.log')}[/cyan]",
            border_style="green",
        )
    )


if __name__ == "__main__":
    main()

