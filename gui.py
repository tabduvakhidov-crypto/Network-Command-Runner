"""
Network Command Runner (GUI)
Modern Tkinter Graphical Interface with Live Progress, Credential Fallback,
and Multi-Device Command Execution.
"""

import os
import sys
import json
import queue
import logging
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List, Dict

from network_engine import (
    extract_valid_ips,
    execute_single_device,
    save_audit_reports,
    ExecutionResult,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
CREDS_PATH = os.path.join(BASE_DIR, "credentials.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


class NetworkCommandRunnerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Network Command Runner - Multi-Device Automation")
        self.root.geometry("1020x760")
        self.root.minsize(900, 650)

        # Apply modern style
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Configure styling
        self.style.configure(".", font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        self.style.configure("Header.TLabel", font=("Segoe UI", 13, "bold"), foreground="#1e3a8a")
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 9), foreground="#4b5563")
        self.style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), foreground="white", background="#2563eb")
        self.style.map("Accent.TButton", background=[("active", "#1d4ed8")])

        # State
        self.is_running = False
        self.stop_requested = False
        self.results_queue = queue.Queue()
        self.current_results: List[ExecutionResult] = []
        self.latest_csv_path = None

        self.credentials: List[Dict] = self.load_credentials()
        self.config: Dict = self.load_config()

        self._build_ui()
        self.root.after(100, self._process_queue)

    def load_config(self) -> Dict:
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "device_type": "cisco_ios",
            "commands": ["crypto key generate rsa modulus 2048", "ip ssh version 2"],
            "save_config": True,
            "save_command": "write memory",
            "max_workers": 10,
            "connect_timeout": 20,
            "banner_timeout": 30,
            "auth_timeout": 30,
            "preflight_port_check": True,
            "mode": "config",
        }

    def load_credentials(self) -> List[Dict]:
        if os.path.exists(CREDS_PATH):
            try:
                with open(CREDS_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _build_ui(self):
        main_frame = ttk.Frame(self.root, padding="12")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(
            header_frame,
            text="Network Command Runner",
            style="Header.TLabel",
        ).pack(anchor=tk.W)
        ttk.Label(
            header_frame,
            text="Execute configuration and operational commands across switches and network devices with automated credential fallback.",
            style="SubHeader.TLabel",
        ).pack(anchor=tk.W)

        # Notebook tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Command Execution
        self.tab_execution = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_execution, text="  Command Execution  ")
        self._build_execution_tab()

        # Tab 2: Credentials Manager
        self.tab_credentials = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_credentials, text="  Credential Profiles  ")
        self._build_credentials_tab()

        # Tab 3: Configuration & Commands
        self.tab_settings = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_settings, text="  Commands & Settings  ")
        self._build_settings_tab()

    def _build_execution_tab(self):
        # Top Split Frame: Left (IPs input) and Right (Summary / Controls)
        top_pane = ttk.Frame(self.tab_execution)
        top_pane.pack(fill=tk.X, pady=(0, 8))

        # Left: IP Paste Area
        ip_group = ttk.LabelFrame(top_pane, text=" Target Device IP Addresses (Paste Here) ", padding=8)
        ip_group.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        ip_toolbar = ttk.Frame(ip_group)
        ip_toolbar.pack(fill=tk.X, pady=(0, 4))

        self.lbl_ip_count = ttk.Label(ip_toolbar, text="Detected: 0 valid IPs", font=("Segoe UI", 9, "bold"), foreground="#2563eb")
        self.lbl_ip_count.pack(side=tk.LEFT)

        btn_paste = ttk.Button(ip_toolbar, text="Paste Clipboard", command=self._paste_clipboard)
        btn_paste.pack(side=tk.RIGHT, padx=2)
        btn_load = ttk.Button(ip_toolbar, text="Load File", command=self._load_ips_file)
        btn_load.pack(side=tk.RIGHT, padx=2)
        btn_clear = ttk.Button(ip_toolbar, text="Clear", command=self._clear_ips)
        btn_clear.pack(side=tk.RIGHT, padx=2)

        self.txt_ips = tk.Text(ip_group, height=6, wrap=tk.WORD, font=("Consolas", 10))
        self.txt_ips.pack(fill=tk.BOTH, expand=True)
        self.txt_ips.bind("<KeyRelease>", self._on_ip_text_changed)

        # Right: Execution Control
        ctrl_group = ttk.LabelFrame(top_pane, text=" Execution Controls ", padding=8)
        ctrl_group.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(6, 0))

        self.lbl_creds_info = ttk.Label(ctrl_group, text=f"Active Credential Sets: {len(self.credentials)}")
        self.lbl_creds_info.pack(anchor=tk.W, pady=2)

        cmds_preview = ", ".join(self.config.get("commands", [])[:2])
        if len(self.config.get("commands", [])) > 2:
            cmds_preview += "..."
        self.lbl_cmd_info = ttk.Label(ctrl_group, text=f"Commands: {cmds_preview or 'None'}")
        self.lbl_cmd_info.pack(anchor=tk.W, pady=2)

        self.lbl_status = ttk.Label(ctrl_group, text="Status: Ready", font=("Segoe UI", 9, "bold"), foreground="#059669")
        self.lbl_status.pack(anchor=tk.W, pady=(4, 6))

        btn_box = ttk.Frame(ctrl_group)
        btn_box.pack(fill=tk.X, pady=4)

        self.btn_start = ttk.Button(btn_box, text="▶ RUN COMMANDS", style="Accent.TButton", command=self._start_execution)
        self.btn_start.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))

        self.btn_stop = ttk.Button(btn_box, text="⏹ Stop", state=tk.DISABLED, command=self._stop_execution)
        self.btn_stop.pack(side=tk.LEFT)

        # Progress bar
        prog_frame = ttk.Frame(self.tab_execution)
        prog_frame.pack(fill=tk.X, pady=(2, 6))

        self.progress_bar = ttk.Progressbar(prog_frame, orient=tk.HORIZONTAL, mode="determinate")
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.lbl_progress_text = ttk.Label(prog_frame, text="0 / 0", width=12)
        self.lbl_progress_text.pack(side=tk.RIGHT)

        # Results Table
        table_frame = ttk.LabelFrame(self.tab_execution, text=" Live Execution Results ", padding=4)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ip", "status", "credential", "duration", "details")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("ip", text="Device IP", anchor=tk.W)
        self.tree.heading("status", text="Status", anchor=tk.CENTER)
        self.tree.heading("credential", text="Credential Used", anchor=tk.W)
        self.tree.heading("duration", text="Time", anchor=tk.CENTER)
        self.tree.heading("details", text="Output / Details", anchor=tk.W)

        self.tree.column("ip", width=140, minwidth=110)
        self.tree.column("status", width=120, minwidth=90, anchor=tk.CENTER)
        self.tree.column("credential", width=160, minwidth=120)
        self.tree.column("duration", width=70, minwidth=60, anchor=tk.CENTER)
        self.tree.column("details", width=400, minwidth=250)

        # Tags styling
        self.tree.tag_configure("SUCCESS", foreground="#15803d", font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("AUTH_FAILED", foreground="#b91c1c", font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("UNREACHABLE", foreground="#b45309", font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("ERROR", foreground="#7e22ce", font=("Segoe UI", 9, "bold"))

        scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self._on_result_double_click)

        # Bottom Bar: Summary & Export Buttons
        bottom_bar = ttk.Frame(self.tab_execution)
        bottom_bar.pack(fill=tk.X, pady=(6, 0))

        self.lbl_counts = ttk.Label(
            bottom_bar,
            text="Completed: 0 | Succeeded: 0 | Auth Failed: 0 | Unreachable: 0 | Errors: 0",
            font=("Segoe UI", 9)
        )
        self.lbl_counts.pack(side=tk.LEFT)

        btn_open_report = ttk.Button(bottom_bar, text="Open CSV Report", command=self._open_csv_report)
        btn_open_report.pack(side=tk.RIGHT, padx=4)

        btn_open_folder = ttk.Button(bottom_bar, text="Open Reports Folder", command=self._open_reports_dir)
        btn_open_folder.pack(side=tk.RIGHT, padx=4)

    def _build_credentials_tab(self):
        desc = ttk.Label(
            self.tab_credentials,
            text="Add your network credential profiles below in the order they should be tried.\n"
                 "If authentication fails with Credential #1, the tool automatically tries Credential #2, and so on.",
            style="SubHeader.TLabel",
        )
        desc.pack(anchor=tk.W, pady=(0, 8))

        creds_box = ttk.Frame(self.tab_credentials)
        creds_box.pack(fill=tk.BOTH, expand=True)

        cols = ("name", "username", "password", "secret")
        self.creds_tree = ttk.Treeview(creds_box, columns=cols, show="headings", selectmode="browse")
        self.creds_tree.heading("name", text="Profile Name")
        self.creds_tree.heading("username", text="Username")
        self.creds_tree.heading("password", text="Password")
        self.creds_tree.heading("secret", text="Enable Secret")

        self.creds_tree.column("name", width=180)
        self.creds_tree.column("username", width=140)
        self.creds_tree.column("password", width=140)
        self.creds_tree.column("secret", width=140)

        c_scroll = ttk.Scrollbar(creds_box, orient=tk.VERTICAL, command=self.creds_tree.yview)
        self.creds_tree.configure(yscrollcommand=c_scroll.set)
        self.creds_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        c_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self._refresh_creds_tree()

        btn_row = ttk.Frame(self.tab_credentials)
        btn_row.pack(fill=tk.X, pady=8)

        ttk.Button(btn_row, text="➕ Add Profile", command=self._add_credential_dialog).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_row, text="✏ Edit Profile", command=self._edit_credential_dialog).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_row, text="🗑 Delete Profile", command=self._delete_credential).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_row, text="⬆ Move Up", command=lambda: self._move_credential(-1)).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_row, text="⬇ Move Down", command=lambda: self._move_credential(1)).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_row, text="💾 Save to credentials.json", command=self._save_credentials_to_file).pack(side=tk.RIGHT, padx=3)

    def _build_settings_tab(self):
        form = ttk.LabelFrame(self.tab_settings, text=" Command & Connection Parameters ", padding=12)
        form.pack(fill=tk.BOTH, expand=True)

        # Device Type
        ttk.Label(form, text="Netmiko Device Type:").grid(row=0, column=0, sticky=tk.W, pady=6)
        self.var_device_type = tk.StringVar(value=self.config.get("device_type", "cisco_ios"))
        dev_combo = ttk.Combobox(
            form,
            textvariable=self.var_device_type,
            values=["cisco_ios", "cisco_xe", "cisco_nxos", "hp_procurve", "aruba_os", "dell_os6", "dell_os10"],
            width=25,
        )
        dev_combo.grid(row=0, column=1, sticky=tk.W, pady=6)

        # Execution Mode
        ttk.Label(form, text="Execution Mode:").grid(row=1, column=0, sticky=tk.W, pady=6)
        self.var_mode = tk.StringVar(value=self.config.get("mode", "config"))
        mode_combo = ttk.Combobox(
            form,
            textvariable=self.var_mode,
            values=["config", "exec"],
            width=25,
            state="readonly"
        )
        mode_combo.grid(row=1, column=1, sticky=tk.W, pady=6)
        ttk.Label(form, text="(config = configure terminal; exec = show/ping/operational commands)", foreground="#6b7280").grid(row=1, column=2, sticky=tk.W, padx=8)

        # Commands list
        ttk.Label(form, text="Commands to Execute\n(one per line):").grid(row=2, column=0, sticky=tk.NW, pady=6)
        self.txt_commands = tk.Text(form, height=5, width=40, font=("Consolas", 10))
        self.txt_commands.grid(row=2, column=1, sticky=tk.W, pady=6)
        current_cmds = self.config.get("commands", ["crypto key generate rsa modulus 2048", "ip ssh version 2"])
        self.txt_commands.insert("1.0", "\n".join(current_cmds))

        # Save Config Checkbox
        self.var_save_config = tk.BooleanVar(value=self.config.get("save_config", True))
        chk_save = ttk.Checkbutton(form, text="Save configuration after execution (write memory)", variable=self.var_save_config)
        chk_save.grid(row=3, column=1, sticky=tk.W, pady=4)

        # Save Command
        ttk.Label(form, text="Save Command:").grid(row=4, column=0, sticky=tk.W, pady=6)
        self.var_save_cmd = tk.StringVar(value=self.config.get("save_command", "write memory"))
        ttk.Entry(form, textvariable=self.var_save_cmd, width=28).grid(row=4, column=1, sticky=tk.W, pady=6)

        # Max Workers
        ttk.Label(form, text="Parallel Worker Threads:").grid(row=5, column=0, sticky=tk.W, pady=6)
        self.var_workers = tk.IntVar(value=self.config.get("max_workers", 10))
        ttk.Spinbox(form, from_=1, to=50, textvariable=self.var_workers, width=10).grid(row=5, column=1, sticky=tk.W, pady=6)

        # Connect Timeout
        ttk.Label(form, text="SSH Timeout (seconds):").grid(row=6, column=0, sticky=tk.W, pady=6)
        self.var_timeout = tk.IntVar(value=self.config.get("connect_timeout", 20))
        ttk.Spinbox(form, from_=5, to=60, textvariable=self.var_timeout, width=10).grid(row=6, column=1, sticky=tk.W, pady=6)

        # Preflight port check
        self.var_preflight = tk.BooleanVar(value=self.config.get("preflight_port_check", True))
        chk_preflight = ttk.Checkbutton(
            form,
            text="Fast Preflight Check (Test TCP port 22 before attempting full SSH handshake)",
            variable=self.var_preflight
        )
        chk_preflight.grid(row=7, column=1, sticky=tk.W, pady=6)

        # Save Settings Button
        ttk.Button(form, text="💾 Save Settings to config.json", command=self._save_settings).grid(row=8, column=1, sticky=tk.W, pady=12)

    # --- IP Handling Methods ---

    def _paste_clipboard(self):
        try:
            content = self.root.clipboard_get()
            self.txt_ips.insert(tk.END, ("\n" if self.txt_ips.get("1.0", tk.END).strip() else "") + content)
            self._on_ip_text_changed()
        except Exception as e:
            messagebox.showwarning("Clipboard Error", f"Could not read from clipboard: {e}")

    def _load_ips_file(self):
        path = filedialog.askopenfilename(
            title="Select Text File with IP Addresses",
            filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.txt_ips.delete("1.0", tk.END)
                self.txt_ips.insert(tk.END, content)
                self._on_ip_text_changed()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def _clear_ips(self):
        self.txt_ips.delete("1.0", tk.END)
        self._on_ip_text_changed()

    def _on_ip_text_changed(self, event=None):
        text = self.txt_ips.get("1.0", tk.END)
        ips = extract_valid_ips(text)
        self.lbl_ip_count.config(text=f"Detected: {len(ips)} valid unique IPs")

    # --- Credentials Management Methods ---

    def _refresh_creds_tree(self):
        for item in self.creds_tree.get_children():
            self.creds_tree.delete(item)
        for c in self.credentials:
            masked_pass = "••••••••" if c.get("password") else ""
            masked_secret = "••••••••" if c.get("secret") else ""
            self.creds_tree.insert(
                "",
                tk.END,
                values=(c.get("name", "Unnamed"), c.get("username", ""), masked_pass, masked_secret),
            )
        self.lbl_creds_info.config(text=f"Active Credential Sets: {len(self.credentials)}")

    def _add_credential_dialog(self):
        self._credential_form_dialog(title="Add Credential Profile")

    def _edit_credential_dialog(self):
        selected = self.creds_tree.selection()
        if not selected:
            messagebox.showinfo("Select Profile", "Please select a credential profile to edit.")
            return
        idx = self.creds_tree.index(selected[0])
        self._credential_form_dialog(title="Edit Credential Profile", cred=self.credentials[idx], index=idx)

    def _credential_form_dialog(self, title: str, cred: Dict = None, index: int = None):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.geometry("380x280")
        dlg.transient(self.root)
        dlg.grab_set()

        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Profile Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        var_name = tk.StringVar(value=cred.get("name", "") if cred else "")
        ttk.Entry(frm, textvariable=var_name, width=28).grid(row=0, column=1, pady=5)

        ttk.Label(frm, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        var_user = tk.StringVar(value=cred.get("username", "") if cred else "")
        ttk.Entry(frm, textvariable=var_user, width=28).grid(row=1, column=1, pady=5)

        ttk.Label(frm, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        var_pass = tk.StringVar(value=cred.get("password", "") if cred else "")
        ttk.Entry(frm, textvariable=var_pass, width=28, show="*").grid(row=2, column=1, pady=5)

        ttk.Label(frm, text="Enable Secret\n(optional):").grid(row=3, column=0, sticky=tk.W, pady=5)
        var_secret = tk.StringVar(value=cred.get("secret", "") if cred else "")
        ttk.Entry(frm, textvariable=var_secret, width=28, show="*").grid(row=3, column=1, pady=5)

        def save():
            name = var_name.get().strip() or "Profile"
            user = var_user.get().strip()
            pw = var_pass.get()
            sec = var_secret.get() or pw
            if not user or not pw:
                messagebox.showerror("Missing Data", "Username and Password are required.", parent=dlg)
                return

            new_data = {"name": name, "username": user, "password": pw, "secret": sec}
            if index is not None:
                self.credentials[index] = new_data
            else:
                self.credentials.append(new_data)
            self._refresh_creds_tree()
            dlg.destroy()

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=4, column=0, columnspan=2, pady=15)
        ttk.Button(btn_row, text="Save Profile", command=save).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT, padx=4)

    def _delete_credential(self):
        selected = self.creds_tree.selection()
        if not selected:
            return
        idx = self.creds_tree.index(selected[0])
        if messagebox.askyesno("Confirm Delete", f"Delete profile '{self.credentials[idx].get('name')}'?"):
            del self.credentials[idx]
            self._refresh_creds_tree()

    def _move_credential(self, delta: int):
        selected = self.creds_tree.selection()
        if not selected:
            return
        idx = self.creds_tree.index(selected[0])
        new_idx = idx + delta
        if 0 <= new_idx < len(self.credentials):
            item = self.credentials.pop(idx)
            self.credentials.insert(new_idx, item)
            self._refresh_creds_tree()
            children = self.creds_tree.get_children()
            self.creds_tree.selection_set(children[new_idx])

    def _save_credentials_to_file(self):
        try:
            with open(CREDS_PATH, "w", encoding="utf-8") as f:
                json.dump(self.credentials, f, indent=2)
            messagebox.showinfo("Saved", "Credentials successfully saved to credentials.json")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save credentials: {e}")

    # --- Settings Methods ---

    def _save_settings(self):
        cmds = [c.strip() for c in self.txt_commands.get("1.0", tk.END).splitlines() if c.strip()]
        self.config = {
            "device_type": self.var_device_type.get(),
            "commands": cmds,
            "mode": self.var_mode.get(),
            "save_config": self.var_save_config.get(),
            "save_command": self.var_save_cmd.get(),
            "max_workers": self.var_workers.get(),
            "connect_timeout": self.var_timeout.get(),
            "banner_timeout": self.config.get("banner_timeout", 30),
            "auth_timeout": self.config.get("auth_timeout", 30),
            "preflight_port_check": self.var_preflight.get(),
        }
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            messagebox.showinfo("Settings Saved", "Configuration saved to config.json")
            # Update preview label
            cmds_preview = ", ".join(cmds[:2])
            if len(cmds) > 2:
                cmds_preview += "..."
            self.lbl_cmd_info.config(text=f"Commands: {cmds_preview or 'None'}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")

    # --- Command Execution ---

    def _start_execution(self):
        if self.is_running:
            return

        ips = extract_valid_ips(self.txt_ips.get("1.0", tk.END))
        if not ips:
            messagebox.showwarning("No Target IPs", "Please paste or enter at least one valid switch IP address.")
            return

        if not self.credentials:
            messagebox.showwarning("No Credentials", "No credentials configured! Go to 'Credential Profiles' tab to add credentials.")
            return

        cmds = [c.strip() for c in self.txt_commands.get("1.0", tk.END).splitlines() if c.strip()]
        if not cmds:
            messagebox.showwarning("No Commands", "No configuration commands specified.")
            return

        confirm_msg = (
            f"Ready to execute commands on {len(ips)} devices.\n\n"
            f"Mode: {self.var_mode.get().upper()}\n"
            f"Commands to apply:\n" + "\n".join(f"  • {c}" for c in cmds) + "\n\n"
            f"Credentials to cycle through: {len(self.credentials)} profiles\n"
            f"Workers: {self.var_workers.get()} threads\n\n"
            "Do you want to proceed?"
        )
        if not messagebox.askyesno("Confirm Execution", confirm_msg):
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.current_results.clear()

        self.is_running = True
        self.stop_requested = False
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.lbl_status.config(text="Status: Running...", foreground="#2563eb")

        self.progress_bar["maximum"] = len(ips)
        self.progress_bar["value"] = 0
        self.lbl_progress_text.config(text=f"0 / {len(ips)}")

        self.config["device_type"] = self.var_device_type.get()
        self.config["commands"] = cmds
        self.config["mode"] = self.var_mode.get()
        self.config["save_config"] = self.var_save_config.get()
        self.config["save_command"] = self.var_save_cmd.get()
        self.config["max_workers"] = self.var_workers.get()
        self.config["connect_timeout"] = self.var_timeout.get()
        self.config["preflight_port_check"] = self.var_preflight.get()

        worker_thread = threading.Thread(
            target=self._run_batch_worker,
            args=(ips, self.credentials, cmds, self.config),
            daemon=True,
        )
        worker_thread.start()

    def _stop_execution(self):
        if self.is_running:
            self.stop_requested = True
            self.lbl_status.config(text="Status: Stopping (waiting for active threads)...", foreground="#b45309")
            self.btn_stop.config(state=tk.DISABLED)

    def _run_batch_worker(self, ips: List[str], credentials: List[Dict], commands: List[str], config: Dict):
        from concurrent.futures import ThreadPoolExecutor, as_completed

        max_workers = config.get("max_workers", 10)
        total = len(ips)
        completed = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(
                    execute_single_device, ip, credentials, commands, config
                ): ip
                for ip in ips
            }

            for future in as_completed(future_to_ip):
                if self.stop_requested:
                    break
                res = future.result()
                completed += 1
                self.results_queue.put(("RESULT", res, completed, total))

        self.results_queue.put(("DONE", None, completed, total))

    def _process_queue(self):
        try:
            while True:
                msg_type, data, completed, total = self.results_queue.get_nowait()
                if msg_type == "RESULT":
                    res: ExecutionResult = data
                    self.current_results.append(res)

                    detail_text = (
                        "Commands executed successfully"
                        if res.status == "SUCCESS"
                        else res.error_message
                    )
                    self.tree.insert(
                        "",
                        tk.END,
                        values=(
                            res.ip,
                            res.status,
                            res.credential_used or "-",
                            f"{res.duration_seconds}s",
                            detail_text,
                        ),
                        tags=(res.status,),
                    )
                    children = self.tree.get_children()
                    if children:
                        self.tree.see(children[-1])

                    self.progress_bar["value"] = completed
                    self.lbl_progress_text.config(text=f"{completed} / {total}")
                    self._update_counts_label()

                elif msg_type == "DONE":
                    self.is_running = False
                    self.btn_start.config(state=tk.NORMAL)
                    self.btn_stop.config(state=tk.DISABLED)
                    self.lbl_status.config(text="Status: Completed", foreground="#059669")

                    if self.current_results:
                        csv_file, _ = save_audit_reports(self.current_results, REPORTS_DIR)
                        self.latest_csv_path = csv_file
                        messagebox.showinfo(
                            "Execution Finished",
                            f"Execution finished on {len(self.current_results)} devices.\n\n"
                            f"Audit summary saved to:\n{csv_file}"
                        )
        except queue.Empty:
            pass

        self.root.after(100, self._process_queue)

    def _update_counts_label(self):
        succ = sum(1 for r in self.current_results if r.status == "SUCCESS")
        auth = sum(1 for r in self.current_results if r.status == "AUTH_FAILED")
        unreach = sum(1 for r in self.current_results if r.status == "UNREACHABLE")
        err = sum(1 for r in self.current_results if r.status == "ERROR")
        self.lbl_counts.config(
            text=f"Total: {len(self.current_results)} | Succeeded: {succ} | Auth Failed: {auth} | Unreachable: {unreach} | Errors: {err}"
        )

    def _on_result_double_click(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        ip = item["values"][0]

        match = next((r for r in self.current_results if r.ip == ip), None)
        if match:
            dlg = tk.Toplevel(self.root)
            dlg.title(f"Device Output - {ip}")
            dlg.geometry("750x550")

            txt = tk.Text(dlg, font=("Consolas", 10), wrap=tk.NONE)
            txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

            content = (
                f"Device IP: {match.ip}\n"
                f"Status: {match.status}\n"
                f"Credential Used: {match.credential_used}\n"
                f"Credential Attempts: {'; '.join(match.attempts)}\n"
                f"Execution Duration: {match.duration_seconds}s\n"
                f"Error Message: {match.error_message or 'None'}\n\n"
                f"=== Raw Device Output ===\n"
                f"{match.raw_output or 'No output recorded.'}"
            )
            txt.insert("1.0", content)
            txt.config(state=tk.DISABLED)

    def _open_csv_report(self):
        if self.latest_csv_path and os.path.exists(self.latest_csv_path):
            os.startfile(self.latest_csv_path)
        else:
            if os.path.exists(REPORTS_DIR):
                csvs = [os.path.join(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR) if f.endswith(".csv")]
                if csvs:
                    latest = max(csvs, key=os.path.getctime)
                    os.startfile(latest)
                    return
            messagebox.showinfo("No Report", "No CSV report available yet. Run execution first.")

    def _open_reports_dir(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.startfile(REPORTS_DIR)


def main():
    root = tk.Tk()
    app = NetworkCommandRunnerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
