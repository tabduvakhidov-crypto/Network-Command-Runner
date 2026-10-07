"""
Switch Vulnerability Remediation Engine
Handles IP parsing, multi-threaded execution, credential cycling,
SSH command execution (Netmiko), and audit logging.
"""

import os
import re
import csv
import time
import socket
import logging
from datetime import datetime
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Callable, Tuple

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)


@dataclass
class RemediationResult:
    ip: str
    status: str  # 'SUCCESS', 'AUTH_FAILED', 'UNREACHABLE', 'ERROR'
    credential_used: Optional[str] = None
    attempts: List[str] = field(default_factory=list)
    error_message: str = ""
    raw_output: str = ""
    duration_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def extract_valid_ips(raw_text: str) -> List[str]:
    """
    Extracts, validates, and deduplicates IPv4 addresses from arbitrary text
    (including multi-line paste, comma-separated lists, tables, etc.).
    Preserves original order.
    """
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_text)
    valid_ips = []
    seen = set()

    for candidate in candidates:
        parts = candidate.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            # Exclude broadcast/invalid loopback/0.0.0.0
            if candidate != "0.0.0.0" and candidate != "255.255.255.255":
                if candidate not in seen:
                    seen.add(candidate)
                    valid_ips.append(candidate)

    return valid_ips


def sanitize_commands(
    raw_commands: List[str],
    current_save_config: bool = True,
    current_save_cmd: str = "write memory",
) -> Tuple[List[str], bool, str]:
    """
    Cleans up user-pasted commands:
    - Removes redundant config mode delimiters ('configure terminal', 'conf t', 'end', 'exit').
    - Extracts save commands ('write memory', 'copy run start') into save_command.
    - Returns (clean_commands, should_save_config, save_command).
    """
    clean_commands = []
    should_save = current_save_config
    save_cmd = current_save_cmd

    for cmd in raw_commands:
        line = cmd.strip()
        if not line:
            continue
        line_lower = line.lower()
        if line_lower in ["configure terminal", "conf t", "config t", "con t"]:
            continue
        if line_lower in ["end", "exit"]:
            continue
        if line_lower in [
            "write memory",
            "write mem",
            "wr",
            "copy running-config startup-config",
            "copy run start",
        ]:
            should_save = True
            save_cmd = line
            continue
        clean_commands.append(line)

    return clean_commands, should_save, save_cmd


def check_port_open(host: str, port: int = 22, timeout: float = 3.0) -> Tuple[bool, str]:
    """
    Fast pre-flight check to see if SSH port 22 is open before attempting full SSH handshake.
    Prevents waiting for full timeouts across multiple credentials on offline devices.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.close()
        return True, ""
    except socket.timeout:
        return False, f"TCP connection timed out ({timeout}s)"
    except ConnectionRefusedError:
        return False, "Connection refused on port 22"
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def remediate_single_switch(
    ip: str,
    credentials: List[Dict],
    commands: List[str],
    config: Dict,
    logger: Optional[logging.Logger] = None,
) -> RemediationResult:
    """
    Connects to a single switch, cycling through credentials until one succeeds.
    Executes commands, saves configuration, and returns a detailed RemediationResult.
    """
    start_time = time.time()
    device_type = config.get("device_type", "cisco_ios")
    timeout = config.get("connect_timeout", 15)
    banner_timeout = config.get("banner_timeout", 15)
    auth_timeout = config.get("auth_timeout", 15)
    save_config = config.get("save_config", True)
    save_command = config.get("save_command", "write memory")
    global_delay = config.get("global_delay_factor", 1.0)
    preflight_check = config.get("preflight_port_check", True)

    attempts = []

    if logger:
        logger.info(f"[{ip}] Starting remediation...")

    # Step 1: Preflight TCP check (fast-fail if offline or port 22 blocked)
    if preflight_check:
        is_open, open_err = check_port_open(ip, port=22, timeout=4.0)
        if not is_open:
            duration = round(time.time() - start_time, 2)
            if logger:
                logger.warning(f"[{ip}] Port 22 unreachable: {open_err}")
            return RemediationResult(
                ip=ip,
                status="UNREACHABLE",
                credential_used=None,
                attempts=["Preflight check failed"],
                error_message=f"Port 22 unreachable: {open_err}",
                duration_seconds=duration,
            )

    # Sanitize commands (strip conf t, end, extract write memory)
    clean_commands, should_save, save_cmd_to_use = sanitize_commands(commands, save_config, save_command)

    # Step 2: Iterate over credentials
    for idx, cred in enumerate(credentials, start=1):
        cred_name = cred.get("name") or f"Cred #{idx} ({cred.get('username')})"
        username = cred.get("username", "")
        password = cred.get("password", "")
        secret = cred.get("secret", password)

        attempts.append(cred_name)
        if logger:
            logger.info(f"[{ip}] Trying credential: {cred_name}...")

        device_params = {
            "device_type": device_type,
            "host": ip,
            "username": username,
            "password": password,
            "secret": secret,
            "conn_timeout": timeout,
            "banner_timeout": banner_timeout,
            "auth_timeout": auth_timeout,
            "global_delay_factor": global_delay,
            "fast_cli": False,
        }

        try:
            with ConnectHandler(**device_params) as net_connect:
                if logger:
                    logger.info(f"[{ip}] Successfully authenticated with {cred_name}!")

                # Enter enable mode if needed and secret provided
                if secret and not net_connect.check_enable_mode():
                    try:
                        net_connect.enable()
                    except Exception as en_err:
                        if logger:
                            logger.warning(f"[{ip}] Enable mode failed with {cred_name}: {en_err}")
                        # If enable fails, treat as auth failure and try next credential
                        attempts.append(f"{cred_name} (Enable failed)")
                        continue

                # Run configuration commands
                command_outputs = []
                command_outputs.append(f"=== Execution on {ip} using {cred_name} ===")
                command_outputs.append(f"Prompt: {net_connect.find_prompt()}")

                if clean_commands:
                    # Check for interactive commands like 'crypto key generate'
                    has_interactive = any("crypto key generate" in cmd.lower() for cmd in clean_commands)
                    if has_interactive:
                        net_connect.config_mode()
                        cfg_lines = []
                        for cmd in clean_commands:
                            if "crypto key generate" in cmd.lower():
                                out = net_connect.send_command_timing(cmd, last_read=3.0, read_timeout=60.0)
                                if any(p in out.lower() for p in ["[yes/no]", "yes/no", "replace them"]):
                                    out += "\n" + net_connect.send_command_timing("yes", last_read=4.0, read_timeout=90.0)
                                elif "how many bits" in out.lower():
                                    out += "\n" + net_connect.send_command_timing("2048", last_read=4.0, read_timeout=90.0)
                                cfg_lines.append(f"{cmd}\n{out}")
                            else:
                                out = net_connect.send_command_timing(cmd, last_read=2.0, read_timeout=30.0)
                                cfg_lines.append(f"{cmd}\n{out}")
                        net_connect.exit_config_mode()
                        config_output = "\n".join(cfg_lines)
                    else:
                        config_output = net_connect.send_config_set(clean_commands)

                    command_outputs.append("--- Configuration Commands Output ---")
                    command_outputs.append(config_output)

                # Save running-config to startup-config if requested
                if should_save:
                    if logger:
                        logger.info(f"[{ip}] Saving configuration...")
                    save_output = ""
                    try:
                        if save_cmd_to_use:
                            save_output = net_connect.send_command(
                                save_cmd_to_use, read_timeout=30.0
                            )
                        else:
                            save_output = net_connect.save_config()
                    except Exception as sv_err:
                        save_output = f"Warning: Failed to save config: {sv_err}"
                    command_outputs.append("--- Save Configuration Output ---")
                    command_outputs.append(save_output)

                full_output = "\n".join(command_outputs)
                duration = round(time.time() - start_time, 2)

                if logger:
                    logger.info(f"[{ip}] Successfully completed remediation in {duration}s!")

                return RemediationResult(
                    ip=ip,
                    status="SUCCESS",
                    credential_used=cred_name,
                    attempts=attempts,
                    raw_output=full_output,
                    duration_seconds=duration,
                )

        except NetmikoAuthenticationException:
            if logger:
                logger.warning(f"[{ip}] Authentication failed with {cred_name}. Trying next...")
            continue

        except NetmikoTimeoutException as timeout_err:
            duration = round(time.time() - start_time, 2)
            if logger:
                logger.error(f"[{ip}] Connection timed out during SSH session: {timeout_err}")
            return RemediationResult(
                ip=ip,
                status="UNREACHABLE",
                credential_used=None,
                attempts=attempts,
                error_message=f"Timeout during SSH negotiation: {str(timeout_err)}",
                duration_seconds=duration,
            )

        except Exception as exc:
            err_str = str(exc)
            # If error appears to be authentication or permission related, try next credential
            if any(k in err_str.lower() for k in ["authentication", "password", "denied", "secret"]):
                if logger:
                    logger.warning(f"[{ip}] Auth issue with {cred_name}: {err_str}. Trying next...")
                continue
            else:
                duration = round(time.time() - start_time, 2)
                if logger:
                    logger.error(f"[{ip}] Unexpected error during {cred_name}: {err_str}")
                return RemediationResult(
                    ip=ip,
                    status="ERROR",
                    credential_used=None,
                    attempts=attempts,
                    error_message=err_str,
                    duration_seconds=duration,
                )

    # All credentials exhausted without success
    duration = round(time.time() - start_time, 2)
    fail_msg = f"All {len(credentials)} credential sets failed authentication."
    if logger:
        logger.error(f"[{ip}] {fail_msg}")

    return RemediationResult(
        ip=ip,
        status="AUTH_FAILED",
        credential_used=None,
        attempts=attempts,
        error_message=fail_msg,
        duration_seconds=duration,
    )


def remediate_batch(
    ips: List[str],
    credentials: List[Dict],
    commands: List[str],
    config: Dict,
    progress_callback: Optional[Callable[[int, int, RemediationResult], None]] = None,
    logger: Optional[logging.Logger] = None,
) -> List[RemediationResult]:
    """
    Executes remediation across multiple switches in parallel using a ThreadPoolExecutor.
    Calls progress_callback(completed_count, total_count, last_result) after each switch completes.
    """
    max_workers = config.get("max_workers", 10)
    total_ips = len(ips)
    results = []

    if logger:
        logger.info(f"Starting batch remediation for {total_ips} switches with {max_workers} worker threads.")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(
                remediate_single_switch, ip, credentials, commands, config, logger
            ): ip
            for ip in ips
        }

        completed = 0
        for future in as_completed(future_to_ip):
            res = future.result()
            results.append(res)
            completed += 1
            if progress_callback:
                progress_callback(completed, total_ips, res)

    # Sort results to match original IP order
    ip_order = {ip: i for i, ip in enumerate(ips)}
    results.sort(key=lambda r: ip_order.get(r.ip, 999999))

    return results


def save_audit_reports(
    results: List[RemediationResult],
    output_dir: str = "reports",
) -> Tuple[str, str]:
    """
    Saves a comprehensive CSV summary report and individual switch logs in the output_dir.
    Returns (csv_filepath, device_logs_dir).
    """
    os.makedirs(output_dir, exist_ok=True)
    device_logs_dir = os.path.join(output_dir, "device_logs")
    os.makedirs(device_logs_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = os.path.join(output_dir, f"remediation_summary_{timestamp}.csv")

    with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp",
            "IP_Address",
            "Status",
            "Credential_Used",
            "Attempts",
            "Duration_Seconds",
            "Error_Message",
        ])
        for r in results:
            writer.writerow([
                r.timestamp,
                r.ip,
                r.status,
                r.credential_used or "N/A",
                "; ".join(r.attempts),
                r.duration_seconds,
                r.error_message,
            ])

    # Save raw switch outputs into device_logs
    for r in results:
        if r.raw_output:
            log_path = os.path.join(device_logs_dir, f"{r.ip}_{timestamp}.log")
            with open(log_path, mode="w", encoding="utf-8") as f:
                f.write(r.raw_output)

    return csv_file, device_logs_dir

