# Network Command Runner

A versatile, multi-threaded network automation tool designed to execute configuration and operational commands across switches, routers, and firewalls with **automated credential fallback**, **direct IP address pasting**, and **audit reporting**.

---

## 🚀 Key Features

- **Multi-Vendor Command Execution**: Run configuration commands (`config t`) or operational/show commands (`show ...`, `ping ...`) across your network fleet.
- **Direct IP Address Pasting**: Simply paste a list of switch/router IPs from Excel, text files, PuTTY, or inventory sheets. The built-in parser automatically filters out comments, subnets, ports, and duplicates.
- **Automated Credential Fallback**: Network devices often have varying legacy credentials. The tool cycles through a prioritized list of credential profiles (`Cred #1` ➔ `Cred #2` ➔ `Cred #3`) until it successfully authenticates.
- **Multi-Threaded Parallel Execution**: Processes 10, 20, or up to 50 devices concurrently, executing network-wide changes in minutes.
- **Fast Pre-Flight Port 22 Check**: Quickly identifies offline or unreachable devices within 2-3 seconds, skipping dead IPs rather than waiting through multiple credential timeouts.
- **Enable Mode & Config Save**: Automatically handles entering Cisco privileged EXEC mode (`enable`) and saving configuration (`write memory` / `copy run start`).
- **Two User Interfaces**:
  - **Desktop GUI (`gui.py`)**: Visual table with live color-coded progress (Green = Success, Red = Auth Fail, Yellow = Unreachable), clipboard paste button, and one-click report exports.
  - **Rich Interactive CLI (`run_commands.py`)**: Terminal interface with progress bars, summary tables, and batch file support.
- **Compliance & Audit Logging**:
  - Auto-generated summary CSV report for IT audit / compliance evidence.
  - Per-device raw logs in `reports/device_logs/` containing the exact CLI output.

---

## 📁 Directory Structure

```text
network-command-runner/
├── gui.py                   # Desktop GUI application
├── run_commands.py          # Terminal CLI tool
├── network_engine.py        # Multi-threaded execution & fallback engine
├── credentials.json         # Configured username/password/secret profiles
├── config.json              # Commands, timeout, mode, and thread settings
├── run_gui.bat              # 1-Click launcher for GUI
├── run_cli.bat              # 1-Click launcher for CLI
└── reports/                 # Auto-generated CSVs and raw device logs
    ├── device_logs/         # Raw CLI output per switch IP
    └── execution_summary_<timestamp>.csv
```

---

## ⚡ Quick Start

### Option 1: Desktop GUI (Recommended)
Double-click `run_gui.bat` or run:
```powershell
python gui.py
```
1. Paste your IP addresses directly into the **Target Device IP Addresses** box.
2. Review/add credentials in the **Credential Profiles** tab.
3. Configure the commands you want to run under **Commands & Settings**.
4. Click **▶ RUN COMMANDS**.
5. Double-click any row to view raw device output, or click **Open CSV Report**.

### Option 2: Interactive Terminal CLI
Double-click `run_cli.bat` or run:
```powershell
python run_commands.py
```
- Paste your IP list directly into the terminal prompt and press Enter on an empty line (or pass `--file ips.txt`).

---

## 🛠 Configuration Modes (`config.json` & GUI)

The tool supports two execution modes:

1. **Configuration Mode (`mode: "config"`)**:
   - Enters configuration mode (`configure terminal`).
   - Executes configuration commands (e.g., `ip ssh version 2`, `crypto key generate rsa modulus 2048`, `vlan 10`, `ntp server ...`).
   - Automatically saves running configuration (`write memory`).
2. **Operational / Exec Mode (`mode: "exec"`)**:
   - Executes show/status commands (e.g., `show ip int brief`, `show version`, `show cdp neighbors`, `show mac address-table`).
   - Captures and saves full command output without modifying switch configurations.
