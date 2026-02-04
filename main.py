#!/usr/bin/env python3
"""
███╗   ██╗███████╗ ██████╗ ███╗   ██╗    ██╗   ██╗ ██████╗ ██╗██████╗ 
████╗  ██║██╔════╝██╔═══██╗████╗  ██║    ██║   ██║██╔═══██╗██║██╔══██╗
██╔██╗ ██║█████╗  ██║   ██║██╔██╗ ██║    ██║   ██║██║   ██║██║██║  ██║
██║╚██╗██║██╔══╝  ██║   ██║██║╚██╗██║    ╚██╗ ██╔╝██║   ██║██║██║  ██║
██║ ╚████║███████╗╚██████╔╝██║ ╚████║     ╚████╔╝ ╚██████╔╝██║██████╔╝
╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═══╝   ╚═════╝ ╚═╝╚═════╝ 
                      XSS RECON SUITE V4.0 - NEON VOID
                             CREATED BY RASHI
"""

import os
import sys
import time
import subprocess
import requests
import json
import concurrent.futures
import threading
import shlex
import shutil
import argparse
import select
import fcntl
import os
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.prompt import Prompt, Confirm
from rich.markup import escape


console = Console()

# Neon Void Color Palette
NEON_PURPLE = "bright_magenta"
NEON_CYAN = "bright_cyan"
NEON_PINK = "bright_red"
NEON_BLUE = "bright_blue"
NEON_YELLOW = "bright_yellow"
NEON_GREEN = "bright_green"

class XSSHuntingTool:
    def __init__(self):
        # Force PD tools to the front of PATH
        go_bin = os.path.expanduser("~/go/bin")
        os.environ["PATH"] = f"{go_bin}:{os.environ['PATH']}"
        
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        # Ensure result directory exists
        if not os.path.exists(os.path.join(self.base_dir, "results")):
            os.makedirs(os.path.join(self.base_dir, "results"))
        self.target = ""
        self.custom_payload_path = ""
        self.manual_payloads = []
        self.waf_enabled = False
        self.logs = []
        self.findings = {
            "subdomains": [],
            "live_hosts": [],
            "urls": [],
            "params": [],
            "hidden_params": [],
            "vulnerabilities": []
        }
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Pentest Tool; NEON VOID V4.0)'})
        self.session.verify = False
        # Shadow sets for O(1) deduplication
        self._subdomain_set = set()
        self._url_set = set()
        self._param_set = set()
        self._hidden_param_set = set()
        
        # New: Map URLs to their parameters (visible + hidden)
        self.url_to_params = {} # {url: set(params)}
        
        self.current_module = "Idle"
        # --- NEW DUAL PROGRESS SYSTEM ---
        self.total_progress = 0    # 0-100 (Overall campaign)
        self.step_progress = 0     # 0-100 (Current module)
        self.step_name = "Idle"    # Current step name
        self.step_progress_target = 0  # For smooth animation
        self._stop_creep = threading.Event()
        
        self.total_scan_duration = 1800 # Default 30 min expectation
        self.eta_string = "CALCULATING..."
        
        self.log_counter = 0
        self.latest_discovery = "Engine Ready"
        self.last_activity = time.time()
        self.scan_start = time.time()
        self.last_ui_update = 0 # Throttle UI updates
        self.scan_completed = False
        
        # Task Completion Percentage Tracking (for fuzzing, etc.)
        self.task_total = 0
        self.task_completed = 0
        
        # New Stats for Feedback
        self.payload_stats = {
            "Basic": 0,
            "Script": 0,
            "Event": 0,
            "Bypass": 0,
            "SVG": 0,
            "Advanced": 0
        }
        self.link_stability = 100.0  # Percentage
        self.data_throughput = 0.0   # requests per second
        
        # Start Progress Creep Thread (for baseline activity)
        threading.Thread(target=self._creep_worker, daemon=True).start()
        
        self.ui_lock = threading.RLock()
        self.active_layout = None
        self.options = [
            ("1", "🎯 SET_TARGET", "Define the primary domain for reconnaissance."),
            ("2", "🚀 AUTO_HUNT", "Execute full-spectrum automated scan."),
            ("3", "🔎 SUBS_FINDER", "Enumerate subdomains and network clusters."),
            ("4", "📡 LIVE_CHECK", "Verify host availability and status codes."),
            ("5", "📦 URL_EXTRACT", "Pull endpoints from archival sources (GAU)."),
            ("6", "🐱 CRAWL_ENGINE", "Perform dynamic crawling and link discovery."),
            ("7", "🕷️ PARAM_MINER", "Extract visible query parameters from URLs."),
            ("8", "🏹 GHOST_PARAMS", "Uncover hidden or unlinked parameters (Arjun)."),
            ("9", "🧪 XSS_FUZZER", "Launch the advanced 3-stage fuzzing kernel."),
            ("P", "💉 PAYLOAD_CFG", "Manage custom payload lists and manual injections."),
            ("S", "🛡️ STEALTH_MODE", "Toggle identity masking and rate limiting."),
            ("V", "📋 SCAN_REPORT", "Review discovered intelligence and vulns."),
            ("I", "🛠️ SYSTEM_SETUP", "Install and update all binary dependencies."),
            ("0", "🚪 SYSTEM_EXIT", "Safely terminate the session.")
        ]

    def startup_sequence(self):
        """Simulate high-tech system boot-up"""
        os.system('clear' if os.name == 'posix' else 'cls')
        steps = [
            ("Initializing Kernels...", 0.2),
            ("Loading Void Payloads...", 0.3),
            ("Establishing Secure Link...", 0.4),
            ("Syncing SAT-RECON Modules...", 0.3),
            ("SYSTEM STANDBY: NEON VOID V4.0", 0.5)
        ]
        
        for msg, delay in steps:
            with console.status(f"[{NEON_PURPLE}]{msg}[/]", spinner="moon"):
                time.sleep(delay)
        
        banner = f"[{NEON_CYAN}]ACCESS GRANTED[/]"
        console.print(Align.center(Panel(banner, border_style=NEON_PURPLE, padding=(1, 5))))
        time.sleep(0.8)

    def detect_waf(self):
        if not self.target: return
        self.log(f"🛡️  Scanning for WAF on {self.target}...", "yellow")
        try:
            url = f"http://{self.target}"
            headers = {'User-Agent': 'Mozilla/5.0 (Pentest Tool)'}
            response = requests.get(url, headers=headers, timeout=5)
            
            waf_headers = [
                'cf-ray', 'cloudflare', 'x-akamai-transformed', 'akamai',
                'x-sucuri-id', 'sucuri', 'x-protected-by', 'incapsula',
                'x-fw-rule', 'mod_security', 'barracuda'
            ]
            
            detected = False
            for header, value in response.headers.items():
                if any(w in header.lower() or w in value.lower() for w in waf_headers):
                    detected = True
                    break
            
            if detected:
                self.waf_enabled = True
                self.log(f"✅ WAF DETECTED! Stealth Mode automatically enabled.", "bold green")
            else:
                self.log("ℹ️ No common WAF headers found. Manual stealth remains optional.", "dim")
        except Exception as e:
            self.log(f"⚠️ WAF Detection failed: {str(e)}", "dim yellow")

    def _creep_worker(self):
        """Smoothly moves progress bar towards target over time"""
        while not self._stop_creep.is_set():
            if self.step_progress < self.step_progress_target:
                with self.ui_lock:
                    self.step_progress += 0.2 # Smooth creep
                if self.step_progress > self.step_progress_target:
                    self.step_progress = self.step_progress_target
            time.sleep(0.1)

    def log(self, message, style="white"):
        msg_lower = str(message).lower()
        
        # Determine icon and semantic style based on content
        icon = "🛰️"
        if "error" in msg_lower or "❌" in msg_lower: 
            icon = "🚫"
            style = f"bold {NEON_PINK}"
        elif "✅" in msg_lower or "completed" in msg_lower or "success" in msg_lower: 
            icon = "⚡"
            style = f"bold {NEON_GREEN}"
        elif "⚠️" in msg_lower or "timeout" in msg_lower: 
            icon = "📡"
            style = f"bold {NEON_YELLOW}"
        elif "vulnerability found" in msg_lower or "confirmed" in msg_lower or "💥" in msg_lower: 
            icon = "☣️"
            style = f"bold {NEON_PINK}"
        elif "running" in msg_lower or "step" in msg_lower or "started" in msg_lower:
            icon = "🚀"
            style = f"bold {NEON_CYAN}"
        elif any(x in msg_lower for x in ["found", "detected", "extracted"]):
            icon = "🧪"
            style = NEON_GREEN

        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # We allow some markup in the message itself (like colors/bold), so we escape only if it doesn't look like markup
        msg_str = str(message)
        if "[" not in msg_str: 
            msg_str = escape(msg_str)
            
        formatted = f"[dim white]{timestamp}[/] {icon} [{style}]{msg_str}[/]"
        
        with self.ui_lock:
            self.logs.append(formatted)
            if len(self.logs) > 25:
                self.logs.pop(0)
            self.log_counter += 1
            self.last_activity = time.time()
            
        # Throttle UI updates to max 5 per second
        if self.active_layout:
            now = time.time()
            if now - self.last_ui_update > 0.2:
                self.update_ui(self.active_layout)
                self.last_ui_update = now
        
        # Emergency bailout: if we haven't seen activity in 10 minutes and we are in a module, it might be stuck
        if not self.scan_completed and self.current_module not in ["Idle", "Scan Finished", "COMPLETE"]:
            if time.time() - self.last_activity > 600:
                 self.log("CRITICAL: Watchdog triggered - No activity for 10 minutes. Bailing.", "red")
                 os._exit(1)

    def make_layout(self, show_detailed_results=False) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="progress", size=6), # NEW Progress Panel
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        if show_detailed_results:
            layout["main"].update(self.get_detailed_results_panel())
        else:
            layout["main"].split_row(
                Layout(name="left_pane", ratio=2),
                Layout(name="logs", ratio=1)
            )
            layout["left_pane"].split_column(
                Layout(name="summary", size=10),
                Layout(name="findings", ratio=1)
            )
        return layout

    def generate_bar(self, percent, width=30, color="cyan"):
        """Manually generating a cool block bar for maximum control"""
        # width is characters
        filled = int((percent / 100) * width)
        empty = width - filled
        
        bar = f"[{color}]" + ("█" * filled) + "[/]" + f"[dim {color}]" + ("░" * empty) + "[/]"
        return bar

    def get_progress_panel(self):
        # Calculate ETA
        elapsed = time.time() - self.scan_start
        if self.total_progress > 2 and self.total_progress < 100:
            total_est = elapsed / (self.total_progress / 100)
            remaining = max(0, total_est - elapsed)
            rem_td = timedelta(seconds=int(remaining))
            self.eta_string = f"{rem_td}"
        elif self.scan_completed:
            self.eta_string = "COMPLETED"
        
        main_bar = self.generate_bar(self.total_progress, width=40, color="magenta")
        step_bar = self.generate_bar(self.step_progress, width=40, color="cyan")
        
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_row(f"[bold cyan]SEGMENT: {self.step_name.upper()}[/] [dim]{int(self.step_progress)}%[/]")
        grid.add_row(step_bar)
        grid.add_row("")
        grid.add_row(f"[bold magenta]CORE PROGRESS[/] [dim]{int(self.total_progress)}%[/] [bold yellow]ETA: {self.eta_string}[/]")
        grid.add_row(main_bar)
        
        return Panel(grid, title=f"[bold {NEON_YELLOW}]⚡ NEURAL LINK FEED[/]", border_style=NEON_PURPLE)

    def get_header_panel(self):
        banner = f"""[bold {NEON_CYAN}]
  ◹      𝗡𝗘𝗢𝗡 𝗩𝗢𝗜𝗗 : 𝗥𝗘𝗖𝗢𝗡      ◸
  ╚════════════════════════════╝[/]"""
        
        e_target = escape(self.target) if self.target else "---"
        target_disp = f"[{NEON_CYAN}]LINK:[/][bold white] {e_target}[/]"
        stealth_disp = f"[{NEON_PURPLE}]CLOAK:[/{NEON_PURPLE}] " + (f"[bold {NEON_GREEN}]ACTIVE[/]" if self.waf_enabled else f"[dim {NEON_PINK}]OFF[/]")
        
        status_line = f"{target_disp}   |   {stealth_disp}"
        module_line = f"[bold {NEON_YELLOW}]MODULE_EXE:[/][bold white] {escape(self.current_module.upper())}[/]"
        
        elapsed_total = int(time.time() - self.scan_start)
        self.data_throughput = self.log_counter / max(1, elapsed_total)
        discovery_trimmed = escape(self.latest_discovery[:65] + "..." if len(self.latest_discovery) > 65 else self.latest_discovery)
        
        elapsed_since_act = int(time.time() - self.last_activity)
        pulse = "◈" if elapsed_since_act < 2 else "◇"
        pulse_color = NEON_GREEN if elapsed_since_act < 2 else NEON_YELLOW
        
        ticker_line = f"[{pulse_color}]{pulse}[/] [dim white]LOG:[/dim white] [{NEON_CYAN}]{discovery_trimmed}[/] [dim]|[/dim] [bold {NEON_YELLOW}]{self.data_throughput:.1f} i/s[/]"

        grid = Table.grid(expand=True)
        grid.add_column(justify="center")
        grid.add_row(banner)
        grid.add_row(status_line)
        grid.add_row(Rule(style=f"dim {NEON_CYAN}"))
        grid.add_row(module_line)
        grid.add_row(ticker_line)
        
        return Panel(grid, border_style=NEON_CYAN, padding=(0, 1))

    def get_logs_panel(self):
        log_text = Text.from_markup("\n".join(self.logs))
        return Panel(log_text, title="[bold white]🛰️ LIVE INTELLIGENCE FEED[/]", border_style="dim cyan")

    def get_results_summary_panel(self):
        table = Table(box=None, expand=True, padding=(0, 1))
        table.add_column("🔍 SECTOR", style="bold white", width=25)
        table.add_column("📊 DATA", justify="center")
        table.add_column("🧪 LATEST_SIGNAL", style="dim white")

        rows = [
            ("NODE_SUB", "Subdomains", "🔍", NEON_CYAN, "subdomains"),
            ("LINK_VFY", "Live Hosts", "📡", NEON_BLUE, "live_hosts"),
            ("END_POINT", "URLs", "🌐", NEON_PURPLE, "urls"),
            ("QUERY_ARG", "Parameters", "🧪", NEON_GREEN, "params"),
            ("GHOST_PRM", "Hidden Args", "🏹", NEON_PINK, "hidden_params"),
            ("VULN_GATE", "XSS Points", "⚠️", f"bold {NEON_PINK}", "vulnerabilities")
        ]

        for label, hint, icon, style, key in rows:
            count = len(self.findings[key])
            latest = "-"
            if self.findings[key]:
                if key == "vulnerabilities":
                    v = self.findings[key][-1]
                    latest = f"{v['url']} -> {v['param']}"
                else:
                    latest = str(self.findings[key][-1])
            else:
                latest = f"[dim]{hint}[/dim]"
            
            display_latest = latest if len(latest) < 50 else latest[:47] + "..."
            display_latest = escape(display_latest)
            
            count_str = f"[{style}]{count}[/]"
            table.add_row(f"{icon} [bold white]{label}[/]", count_str, display_latest)

        # Payload Distribution Section
        if self.task_total > 0:
            table.add_row(Rule(style="dim white"), "", "")
            stats_line = " ".join([f"[dim {NEON_YELLOW}]{k}:[/][bold white]{v}[/]" for k, v in self.payload_stats.items() if v > 0])
            if stats_line:
                table.add_row("🧪 PAYLOAD_DIST", "", stats_line)

        return Panel(table, title="[bold white]📡 INTELLIGENCE DASHBOARD[/]", border_style=NEON_BLUE)

    def get_detailed_results_panel(self):
        table = Table(
            expand=True, 
            border_style=NEON_PINK,
            header_style=f"bold white on {NEON_PINK}",
            box=None
        )
        table.add_column("🔥 TYPE", style=f"bold {NEON_YELLOW}", width=12)
        table.add_column("🔗 TARGET URL", style=NEON_CYAN, width=45)
        table.add_column("🔑 PARAM", style=f"bold {NEON_PURPLE}", width=12)
        table.add_column("💉 PAYLOAD", style=NEON_GREEN)
        table.add_column("⚖️ CONF", style="bold white", justify="center")

        if not self.findings["vulnerabilities"]:
            table.add_row("-", "[dim]Listening for incoming vulnerability data...[/dim]", "-", "-", "-")
        else:
            for v in self.findings["vulnerabilities"]:
                conf = v.get("confidence", "HIGH")
                conf_styled = f"[bold {NEON_GREEN}]{conf}[/]" if conf == "HIGH" else f"[bold {NEON_YELLOW}]{conf}[/]"
                table.add_row(
                    v["type"].upper(), 
                    escape(v["url"]), 
                    escape(v["param"]), 
                    escape(v["payload"]),
                    conf_styled
                )

        return Panel(table, title=f"[bold {NEON_PINK}]☣️ ALERT_BUFFER[/]", border_style=NEON_PINK)

    def get_footer_panel(self, interactive=False):
        s_count = len(self.findings["subdomains"])
        u_count = len(self.findings["urls"])
        p_count = len(self.findings["params"])
        v_count = len(self.findings["vulnerabilities"])
        
        if self.scan_completed:
            text = f"[bold {NEON_GREEN}]✅ SCANNING IS DONE: 100%[/] | [white]Found: {s_count} Subs, {u_count} URLs, {v_count} Vulns[/white] | [blink {NEON_YELLOW}]READY - PRESS [ENTER][/]"
        else:
            prog = int(self.total_progress)
            color = NEON_GREEN if prog == 100 else NEON_CYAN
            
            metrics = f"[{NEON_CYAN}]Subs: {s_count}[/]  •  [{NEON_YELLOW}]URLs: {u_count}[/]  •  [{NEON_PURPLE}]Prm: {p_count}[/]  •  [{NEON_PINK}]Vul: {v_count}[/]"
            text = f"[bold {color}]OVERALL: {prog}%[/]  [dim]|[/dim]  {metrics}"
            
            if self.total_progress == 0 and not self.current_module:
                 text = f"[bold dim white]STATUS_READY[/] | [bold {NEON_CYAN}]NEON_VOID V4.0[/] | [bold dim white]BY RASHI[/]"
                
        return Align.center(text)

    def get_final_metrics_panel(self, label):
        """Creates a professional final confirmation panel with all metrics"""
        table = Table(box=None, expand=False)
        table.add_column("SYTEM_METRIC", style=f"{NEON_CYAN} bold")
        table.add_column("LOG_VALUE", style="white bold", justify="right")
        
        table.add_row("🎯 TARGET_CORE", escape(self.target))
        table.add_row("🛠️ SCAN_PROTOCOL", escape(label.upper()))
        table.add_row("🌐 NODE_SUB_DISC", str(len(self.findings["subdomains"])))
        table.add_row("📡 LINK_VFY_LIVE", str(len(self.findings["live_hosts"])))
        table.add_row("🔗 END_POINT_EXT", str(len(self.findings["urls"])))
        table.add_row("🔑 QUERY_ARG_MIN", str(len(self.findings["params"])))
        table.add_row("🏹 GHOST_PRM_FND", str(len(self.findings["hidden_params"])))
        
        v_count = len(self.findings["vulnerabilities"])
        v_style = f"bold {NEON_PINK}" if v_count > 0 else f"bold {NEON_GREEN}"
        table.add_row("☣️ VULN_GATES_OPN", f"[{v_style}]{v_count}[/]")
        
        table.add_row("", "")
        table.add_row("🏁 STATUS", f"[bold {NEON_GREEN}]PROTOCOL_COMPLETE[/]")
        
        return Panel(
            Align.center(table),
            title=f"[bold {NEON_GREEN}]✅ MISSION_REPORT_SYNC[/]",
            border_style=NEON_GREEN,
            padding=(1, 4)
        )

    def show_menu(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        banner = f"""[bold {NEON_PURPLE}]
   ██╗  ██╗███████╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗██╗███╗   ██╗ ██████╗ 
   ╚██╗██╔╝██╔════╝██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝ 
    ╚███╔╝ ███████╗███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   ██║██╔██╗ ██║██║  ███╗
    ██╔██╗ ╚════██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██║██║╚██╗██║██║   ██║
   ██╔╝ ██╗███████║███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║██║ ╚████║╚██████╔╝
   ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
 [/] [bold {NEON_YELLOW}]                                 N E O N   V O I D   E D I T I O N[/]"""
        console.print(Align.center(banner))
        
        # System Info Bar
        info_table = Table.grid(expand=True)
        info_table.add_column(justify="left", style=f"dim {NEON_CYAN}")
        info_table.add_column(justify="right", style=f"dim {NEON_CYAN}")
        
        status = f"CORE_TARGET: [bold white]{self.target if self.target else 'NOT_SET'}[/]  |  STEALTH_PROTOCOL: [bold white]{'ENABLED' if self.waf_enabled else 'DISABLED'}[/]"
        info_table.add_row(status, f"v4.2  |  BY [bold {NEON_PURPLE}]RASHI[/]")
        
        console.print(info_table)
        console.print(Rule(style=f"dim {NEON_CYAN}"))
        
        # Menu Grid
        menu_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        menu_table.add_column("Key", style=f"bold {NEON_PINK}", justify="center", width=4)
        menu_table.add_column("Action", style="bold white", width=20)
        menu_table.add_column("Description", style=f"dim {NEON_CYAN}")
        
        # Divide menu into functional groups
        groups = [
            ("RECONNAISSANCE PROTOCOLS", self.options[:2]),
            ("DISCOVERY MODULES", self.options[2:6]),
            ("PARAMETER ANALYSIS", self.options[6:8]),
            ("EXPLOITATION KERNEL", self.options[8:9]),
            ("SYSTEM CONFIGURATION", self.options[9:])
        ]

        for title, opts in groups:
            menu_table.add_row("", f"[bold underline {NEON_PURPLE}]{title}[/]", "")
            for k, a, d in opts:
                menu_table.add_row(f"[{k}]", f"{a}", f"→ {d}")
            menu_table.add_row("", "", "")
            
        console.print(Panel(menu_table, border_style=NEON_PURPLE, padding=(1, 2)))
        console.print(f"[bold {NEON_CYAN}]❯[/] [blink bold white]Awaiting system command...[/]")

    def run(self):
        self.startup_sequence()
        while True:
            self.show_menu()
            choice = Prompt.ask("").strip().upper()
            
            if choice == "0":
                console.print(f"[bold {NEON_YELLOW}]Terminating Session... Safe Journey.[/]")
                break
                
            if choice == "1":
                target_input = Prompt.ask(f"[bold {NEON_YELLOW}]Enter Target Domain[/]").strip()
                if target_input:
                    self.target = target_input
                    self.findings = {
                        "subdomains": [], 
                        "live_hosts": [], 
                        "urls": [], 
                        "params": [], 
                        "hidden_params": [], 
                        "vulnerabilities": []
                    }
                    self._subdomain_set.clear()
                    self._url_set.clear()
                    self._param_set.clear()
                    self._hidden_param_set.clear()
                    # Reset findings for new target
                    self.detect_waf()
                    time.sleep(2)
                continue
                
            if choice == "S":
                self.waf_enabled = not self.waf_enabled
                continue

            if choice == "V":
                self.view_results_static()
                continue

            if choice == "I":
                self.run_installer()
                continue

            if choice == "P":
                self.configure_payloads()
                continue

            if not self.target:
                console.print("[bold red]ERROR: Please set a target first (Option 1)[/]")
                time.sleep(2)
                continue

            valid_choices = [o[0] for o in self.options if o[0] not in ["1", "S", "V", "I", "P", "0"]]
            if choice in valid_choices:
                self.execute_module(choice)
            else:
                console.print("[bold red]Invalid option![/]")
                time.sleep(1)

    def view_results_static(self):
        layout = self.make_layout(show_detailed_results=True)
        layout["header"].update(self.get_header_panel())
        layout["footer"].update(Panel(Align.center(f"[bold {NEON_YELLOW}]PRESS ENTER TO RETURN TO COMMAND_CENTER[/]"), border_style=f"dim {NEON_CYAN}"))
        
        with Live(layout, screen=True, refresh_per_second=4):
            input()

    def execute_module(self, choice):
        label = next(o[1] for o in self.options if o[0] == choice)
        self.current_module = label
        
        layout = self.make_layout()
        self.active_layout = layout
        self.step_progress = 0
        self.step_progress_target = 0
        self.total_progress = 0
        self.log_counter = 0
        self.log(f"Engaging {label} on {self.target}...", "cyan")

        with Live(layout, refresh_per_second=4, screen=True):
            try:
                if choice == "2": self.run_full_auto()
                elif choice == "3": self.run_subfinder_standalone()
                elif choice == "4": self.run_httpx()
                elif choice == "5": self.run_gau_wayback()
                elif choice == "6": self.run_katana_hakrawler()
                elif choice == "7": self.run_paraspider()
                elif choice == "8": self.run_arjun()
                elif choice == "9": self.run_fuzzing()
                
                # Reset task counters after module
                self.task_total = 0
                self.task_completed = 0
                
                self.step_progress = 100
                self.total_progress = 100
                self.log(f"✅ Module {label} completed.", "bold green")
                self.current_module = "Scan Finished"
                
                layout["footer"].update(self.get_footer_panel(interactive=True))
                self.update_ui()
                time.sleep(1.5) 
            except KeyboardInterrupt:
                self.log("⚠️ Scan interrupted by user.", "bold yellow")
            except Exception as e:
                self.log(f"❌ Error in {label}: {str(e)}", "bold red")
                time.sleep(3)
            finally:
                self.active_layout = None

        # Post-scan interaction OUTSIDE of Live/Screen mode
        console.clear()
        # Show a beautiful banner and the final metrics
        banner = """[bold cyan]
  ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗     ███████╗████████╗███████╗
 ██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║     ██╔════╝╚══██╔══╝██╔════╝
 ██║     ██║   ██║██╔████╔██║██████╔╝██║     █████╗     ██║   █████╗  
 ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝     ██║   ██╔══╝  
 ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗███████╗   ██║   ███████╗
  ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚══════╝
[/]"""
        console.print(Align.center(banner))
        console.print(Rule(title="[bold green]TASK COMPLETED[/]", style="dim green"))
        
        # Show the summary panel
        console.print("\n")
        console.print(Align.center(self.get_final_metrics_panel(label)))
        console.print("\n")
        
        console.print(Rule(style="dim cyan"))
        console.print("[bold yellow]What would you like to do next?[/]")
        console.print("[bold cyan][ENTER][/] Return to Main Menu")
        console.print("[bold red][Ctrl+C][/] Exit Tool Safely")
        
        try:
            input()
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Returning to menu...[/]")
            time.sleep(1)
        
        self.post_scan_actions()

    def post_scan_actions(self):
        if not Confirm.ask("\n[bold yellow]Do you want to save these findings?[/]"):
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"recon_{self.target}_{timestamp}"
        
        # Save JSON
        json_file = f"{base_filename}.json"
        try:
            with open(json_file, "w") as f:
                json.dump(self.findings, f, indent=4)
            self.log(f"✅ JSON findings saved to {json_file}", "green")
        except Exception as e:
            self.log(f"❌ Error saving JSON: {str(e)}", "red")

        # Save Markdown Report
        md_file = f"{base_filename}.md"
        try:
            with open(md_file, "w") as f:
                f.write(f"# XSS Recon Report: {self.target}\n")
                f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## 📊 Summary\n")
                f.write(f"- **Subdomains:** {len(self.findings['subdomains'])}\n")
                f.write(f"- **URLs Found:** {len(self.findings['urls'])}\n")
                f.write(f"- **Parameters Found:** {len(self.findings['params'])}\n")
                f.write(f"- **Hidden Parameters:** {len(self.findings['hidden_params'])}\n")
                f.write(f"- **Vulnerabilities Found:** {len(self.findings['vulnerabilities'])}\n\n")

                if self.findings["vulnerabilities"]:
                    f.write("## ☣️ Vulnerabilities\n")
                    f.write("| Type | Param | Payload | Context | URL |\n")
                    f.write("|------|-------|---------|---------|-----|\n")
                    for v in self.findings["vulnerabilities"]:
                        ctx = v.get("context", "N/A")
                        f.write(f"| {v['type']} | `{v['param']}` | `{v['payload']}` | {ctx} | {v['url']} |\n")
                else:
                    f.write("## ✅ No Vulnerabilities Found\n")
                
                f.write("\n## 🌐 Subdomains\n")
                for s in self.findings["subdomains"]: f.write(f"- {s}\n")
            
            self.log(f"✅ Markdown report saved to {md_file}", "green")
        except Exception as e:
            self.log(f"❌ Error saving Markdown: {str(e)}", "red")
        
        time.sleep(2)

    def run_installer(self):
        """Install all required tools and dependencies."""
        os.system('clear' if os.name == 'posix' else 'cls')
        console.print(Rule("[bold cyan]COMMAND_CENTER: RECRUITMENT_PROTOCOL[/]", style="cyan"))
        console.print(Align.center(f"[bold {NEON_PURPLE}]Preparing to install system dependencies...[/]\n"))
        
        if not Confirm.ask("[bold yellow]This will install Go tools and Python packages. Continue?[/]"):
            return

        # 1. Python Packages
        console.print(f"\n[bold {NEON_CYAN}]📦 STEP 1: Updating Python Environment...[/]")
        py_deps = ["requests", "beautifulsoup4", "rich"]
        for dep in py_deps:
            console.print(f"  [dim]Installing {dep}...[/]")
            subprocess.run([sys.executable, "-m", "pip", "install", dep, "--quiet"])
        console.print(f"[bold {NEON_GREEN}]✅ Python environment updated.[/]")

        # 2. Go Tools
        console.print(f"\n[bold {NEON_CYAN}]🚀 STEP 2: Deploying Go Reinforcements...[/]")
        go_tools = {
            "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "gau": "github.com/lc/gau/v2/cmd/gau@latest",
            "waybackurls": "github.com/tomnomnom/waybackurls@latest",
            "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
            "arjun": "github.com/s0md3v/Arjun@latest"
        }
        
        if shutil.which("go"):
            for tool, path in go_tools.items():
                console.print(f"  [dim]Deploying {tool}...[/]")
                subprocess.run(["go", "install", "-v", path], capture_output=True)
            console.print(f"[bold {NEON_GREEN}]✅ Go tools deployed to ~/go/bin.[/]")
        else:
            console.print(f"[bold {NEON_PINK}]❌ Error: Go language not found. Please install Go first.[/]")

        # 3. ParamSpider Special Handling
        console.print(f"\n[bold {NEON_CYAN}]🕷️ STEP 3: Initializing ParamSpider...[/]")
        ps_path = os.path.join(self.base_dir, "ParamSpider")
        if not os.path.exists(ps_path):
            console.print(f"  [dim]Cloning ParamSpider...[/]")
            subprocess.run(["git", "clone", "https://github.com/devanshbatham/ParamSpider", ps_path], capture_output=True)
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", f"{ps_path}/requirements.txt", "--quiet"])
        else:
            console.print(f"  [dim]ParamSpider already present. Ensuring dependencies...[/]")
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", f"{ps_path}/requirements.txt", "--quiet"])
        console.print(f"[bold {NEON_GREEN}]✅ ParamSpider initialized.[/]")

        console.print(f"\n[bold {NEON_GREEN}]🏁 DEPLOYMENT_COMPLETE. SYSTEM_STABLE.[/]")
        input("\n[bold yellow]Press Enter to return to Command Center...[/]")

    def configure_payloads(self):
        """Configure manual payloads or a custom payload file."""
        os.system('clear' if os.name == 'posix' else 'cls')
        console.print(Rule("[bold cyan]PAYLOAD_CONFIGURATION_MODULE[/]", style="cyan"))
        
        console.print("\n[bold white]Current Payload Status:[/]")
        if self.manual_payloads:
            console.print(f"  [bold green]● MANUAL_ENTRY:[/][white] {len(self.manual_payloads)} payloads active.")
        elif self.custom_payload_path:
            console.print(f"  [bold green]● CUSTOM_FILE:[/][white] {self.custom_payload_path}")
        else:
            console.print(f"  [bold yellow]● DEFAULT_SOURCE:[/][white] payloads.json (Auto-failback)")

        table = Table(box=None, header_style=f"bold {NEON_CYAN}")
        table.add_column("Key", style=f"bold {NEON_PINK}")
        table.add_column("Action")
        
        table.add_row("[1]", "Enter Manual Payloads (Comma-separated)")
        table.add_row("[2]", "Set Custom Payload File Path (.txt or .json)")
        table.add_row("[3]", "Reset to Default (payloads.json)")
        table.add_row("[B]", "Back to Main Menu")
        
        console.print(Panel(table, border_style=NEON_PURPLE))
        
        choice = Prompt.ask(f"[bold {NEON_CYAN}]Select Action[/]").strip().upper()
        
        if choice == "1":
            raw = Prompt.ask(f"[bold {NEON_YELLOW}]Enter payloads (separated by ,)[/]").strip()
            if raw:
                self.manual_payloads = [p.strip() for p in raw.split(",") if p.strip()]
                self.custom_payload_path = ""
                console.print(f"[bold green]✅ Loaded {len(self.manual_payloads)} manual payloads.[/]")
        elif choice == "2":
            path = Prompt.ask(f"[bold {NEON_YELLOW}]Enter file path[/]").strip()
            if os.path.exists(path):
                self.custom_payload_path = path
                self.manual_payloads = []
                console.print(f"[bold green]✅ Path set to: {path}[/]")
            else:
                console.print(f"[bold red]❌ Error: File not found.[/]")
        elif choice == "3":
            self.manual_payloads = []
            self.custom_payload_path = ""
            console.print(f"[bold green]✅ Reset to default system payloads.[/]")
        
        time.sleep(1.5)

    def update_ui(self, layout=None):
        target_layout = layout or self.active_layout
        if not target_layout: return
        
        with self.ui_lock:
            target_layout["header"].update(self.get_header_panel())
            try:
                # Use recursive approach to find layout sections
                def update_recursive(l):
                    if l.name == "logs": l.update(self.get_logs_panel())
                    if l.name == "summary": l.update(self.get_results_summary_panel())
                    if l.name == "findings": l.update(self.get_detailed_results_panel())
                    if l.name == "progress": l.update(self.get_progress_panel()) 
                    for child in l.children: update_recursive(child)
                
                update_recursive(target_layout)
            except:
                pass

    def is_dependency_met(self, tool_name):
        """Checks if a critical external tool is installed and in PATH."""
        return shutil.which(tool_name) is not None

    def run_cmd(self, cmd, start_pct=None, end_pct=None, timeout=300, capture_output=False, max_findings=None):
        if start_pct is not None: 
            self.step_progress = start_pct
        if end_pct is not None:
            self.step_progress_target = end_pct
        
        try:
            start_real = datetime.now()
            start_time = time.time()
            # self.log(f"🚀 {cmd.split()[0].upper()} INITIATED...", "cyan bold")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=False, shell=True)
            
            # Make stdout non-blocking
            fd = process.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            
            output_lines = []
            target_domain = self.target.split(':')[0] if ':' in self.target else self.target
            domain_part = target_domain.split('.')[-2] if '.' in target_domain else target_domain
            
            findings_count = 0
            last_out_time = time.time()
            line_buffer = b""
            
            while True:
                # Use select for efficient waiting
                r, _, _ = select.select([process.stdout], [], [], 0.5)
                
                if process.stdout in r:
                    try:
                        chunk = os.read(fd, 4096)
                        if chunk:
                            last_out_time = time.time()
                            line_buffer += chunk
                            while b"\n" in line_buffer:
                                line_bytes, line_buffer = line_buffer.split(b"\n", 1)
                                line = line_bytes.decode('utf-8', errors='ignore').strip()
                                
                                if not line: continue
                                
                                is_finding = False
                                self.last_activity = time.time()
                                low_line = line.lower()
                                
                                # Discovery logic
                                if "." in low_line and domain_part in low_line:
                                    segments = low_line.split()
                                    for found in segments:
                                        found = found.strip("[]()\"' ")
                                        if self.target in found and found not in self._subdomain_set:
                                            with self.ui_lock:
                                                self._subdomain_set.add(found)
                                                self.findings["subdomains"].append(found)
                                                self.latest_discovery = found
                                            is_finding = True
                                
                                if "http" in low_line:
                                    segments = line.split()
                                    for seg in segments:
                                        if seg.startswith("http"):
                                            url = seg.strip("[]()\"'")
                                            if self.is_valid_url(url) and url not in self._url_set:
                                                with self.ui_lock:
                                                    self._url_set.add(url)
                                                    self.findings["urls"].append(url)
                                                    self.latest_discovery = url
                                                    if url not in self.url_to_params:
                                                        self.url_to_params[url] = set()
                                                    self.extract_params_from_url(url)
                                                is_finding = True

                                if is_finding:
                                    findings_count += 1
                                    if start_pct is not None and end_pct is not None and self.step_progress < end_pct:
                                        nudge = (end_pct - start_pct) / 2000 
                                        with self.ui_lock:
                                            self.step_progress = min(end_pct, self.step_progress + nudge)
                                    
                                    if findings_count % 500 == 0:
                                        self.log(f"⚡ [SPEED] {cmd.split()[0].upper()} reached {findings_count} findings...")

                                    if max_findings and findings_count >= max_findings:
                                        self.log(f"🛑 [CAP] Reached {max_findings} for {cmd.split()[0].upper()}.")
                                        process.terminate()
                                        break
                                
                                if capture_output:
                                    output_lines.append(line)
                        elif process.poll() is not None:
                            break
                    except (BlockingIOError, InterruptedError):
                        pass
                    except Exception as e:
                        # self.log(f"Read error: {str(e)}", "dim red")
                        break

                if process.poll() is not None:
                    # Final check for remaining output in buffer
                    if line_buffer:
                        line = line_buffer.decode('utf-8', errors='ignore').strip()
                        if line and capture_output: output_lines.append(line)
                    break
                    
                if time.time() - last_out_time > 60:
                    self.log(f"⚠️ {cmd.split()[0].upper()} HUNG (No Output)", "bold red")
                    process.terminate()
                    break
                    
                if time.time() - start_time > timeout:
                    self.log(f"⚠️ {cmd.split()[0].upper()} TIMED OUT", "bold red")
                    process.terminate()
                    break
            
            process.wait()
            end_real = datetime.now()
            duration = (end_real - start_real).total_seconds()
            self.log(f"⏱️ COMPLETED: {cmd.split()[0].upper()} in {duration:.2f}s", "dim green")
            return output_lines
        except Exception as e:
            self.log(f"❌ Execution Error: {str(e)}")
            return []

    def is_valid_url(self, url):
        # Scale-Optimized Check
        if not url or len(url) > 1024: return False
        
        # Fast rejection by substring (very cheap)
        if "http" not in url: return False
        
        url_lower = url.lower()
        if self.target not in url_lower: return False
        
        # Instant rejection for non-web protocols
        if url_lower.startswith(("data:", "mailto:", "tel:", "javascript:", "blob:")):
            return False
            
        # Extension blacklist (fastest with endswith tuple)
        static_exts = (
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.js', '.woff', '.woff2', 
            '.ttf', '.pdf', '.zip', '.ico', '.txt', '.map', '.mp4', '.mp3', '.exe',
            '.png', '.webp', '.dmg', '.pkg', '.csv', '.xml', '.json', '.sh', '.py'
        )
        
        # Check path before query string to avoid missing parameters like file.php?name=x
        path = url_lower.split('?', 1)[0]
        if path.endswith(static_exts):
            return False
        return True

    def extract_params_from_url(self, url):
        if "?" not in url: return
        try:
            params_part = url.split("?", 1)[1]
            if not params_part: return
            
            # Fast parameter extraction without redundant lookups
            new_params = set()
            for pair in params_part.split("&"):
                if "=" in pair:
                    pname = pair.split("=", 1)[0]
                    if pname and pname not in self._param_set:
                        new_params.add(pname)
            
            if new_params:
                with self.ui_lock:
                    if url not in self.url_to_params:
                        self.url_to_params[url] = set()
                    self.url_to_params[url].update(new_params)
                    for p in new_params:
                        if p not in self._param_set:
                            self._param_set.add(p)
                            self.findings["params"].append(p)
        except:
            pass

    def run_subfinder_standalone(self):
        self.run_subfinder(start_pct=0, end_pct=100)

    def run_subfinder(self, start_pct=0, end_pct=100):
        if not self.is_dependency_met("subfinder"): return
        self.log(f"🔍 Starting Subfinder on {self.target} (Speed-Optimized)...", "yellow")
        target_quoted = shlex.quote(self.target)
        cmd = f"subfinder -d {target_quoted} -silent -t 100"
        self.run_cmd(cmd, start_pct=start_pct, end_pct=end_pct, timeout=180)
        self.log(f"✅ Subdomain discovery complete.", "green")

    def run_httpx(self, start_pct=0, end_pct=100):
        if not self.findings["subdomains"]:
            self.log("⚠️ No subdomains found. Running on main target instead...", "yellow")
            domains_to_check = [self.target]
        else:
            domains_to_check = self.findings["subdomains"]
        
        temp_file = f"temp_subs_{int(time.time())}.txt"
        with open(temp_file, "w") as f:
            for s in domains_to_check: f.write(s + "\n")
        
        if not self.is_dependency_met("httpx"): 
            self.log("⚠️ httpx missing. Using fallback for live host verification.", "yellow")
            # Minimal fallback: assume target is alive
            self.findings["live_hosts"] = [f"http://{self.target}", f"https://{self.target}"]
            if os.path.exists(temp_file): os.remove(temp_file)
            return

        self.log("📡 Verifying live hosts with HTTPX (Parallel)...", "yellow")
        cmd = f"httpx -l {temp_file} -silent -t 100 -rl 150 -no-color"
        # Since run_httpx doesn't directly return a list but populates self.findings["live_hosts"]
        # we need to make sure run_cmd's iterator logic populates it or we read the output.
        # Fixed logic: capture_output=True to process results
        output = self.run_cmd(cmd, start_pct=start_pct, end_pct=end_pct, timeout=300, capture_output=True)
        for host in output:
            host_clean = host.strip()
            if host_clean.startswith("http") and host_clean not in self._url_set:
                with self.ui_lock:
                    self._url_set.add(host_clean)
                    self.findings["urls"].append(host_clean)
            if host_clean and host_clean not in self.findings["live_hosts"]:
                self.findings["live_hosts"].append(host_clean)
        
        self.log(f"✅ {len(self.findings['live_hosts'])} live hosts verified.", "green")
        if os.path.exists(temp_file): os.remove(temp_file)

    def run_gau_wayback(self, start_pct=0, end_pct=100):
        self.log(f"📦 Fetching URLs (GAU/Wayback) for {self.target}...", "yellow")
        target_quoted = shlex.quote(self.target)
        
        # Parallel Execution of Archiving Tools with Capped Scale
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            tasks = []
            if self.is_dependency_met("gau"):
                tasks.append(executor.submit(self.run_cmd, f"gau {target_quoted} --subs -t 20", start_pct=start_pct, end_pct=end_pct, timeout=300, max_findings=5000))
            if self.is_dependency_met("waybackurls"):
                tasks.append(executor.submit(self.run_cmd, f"waybackurls {target_quoted}", start_pct=start_pct, end_pct=end_pct, timeout=300, max_findings=5000))
            
            concurrent.futures.wait(tasks)
            
        self.log(f"✅ Finished archiving phase. Total: {len(self.findings['urls'])}", "green")

    def run_katana_hakrawler(self, start_pct=0, end_pct=100, custom_target=None):
        target = custom_target or self.target
        self.log(f"🐱 Active Crawl (Katana) on {target}...", "yellow")
        target_quoted = shlex.quote(target)
        
        # Use only Katana for speed in full auto, it is more modern
        if self.is_dependency_met("katana"):
            self.run_cmd(f"katana -u {target_quoted} -silent -d 2 -c 20 -timeout 2", start_pct=start_pct, end_pct=end_pct, timeout=120)
            self.log(f"✅ Active crawl complete for {target}.", "dim green")

    def run_paraspider(self, start_pct=0, end_pct=100, custom_target=None):
        target = custom_target or self.target
        self.log(f"🕷️ Mining parameters with ParamSpider on {target}...", "yellow")
        paramspider_path = os.path.join(self.base_dir, "ParamSpider", "paramspider", "main.py")
        if os.path.exists(paramspider_path):
            target_quoted = shlex.quote(target)
            # Use lower level for faster scan in full auto
            cmd = f"python3 {paramspider_path} -d {target_quoted} --level low"
            self.run_cmd(cmd, start_pct=start_pct, end_pct=end_pct, timeout=120)
            
            # PARSE RESULTS
            results_file = f"results/{target}.txt"
            if os.path.exists(results_file):
                try:
                    with open(results_file, "r") as f:
                        for line in f:
                            url = line.strip()
                            if self.is_valid_url(url) and url not in self._url_set:
                                with self.ui_lock:
                                    self._url_set.add(url)
                                    self.findings["urls"].append(url)
                                    if url not in self.url_to_params:
                                        self.url_to_params[url] = set()
                                    self.extract_params_from_url(url)
                    self.log(f"✅ ParamSpider parsed {results_file}.", "dim green")
                except Exception as e:
                    self.log(f"⚠️ Error parsing ParamSpider results: {str(e)}", "dim red")
            
            self.log(f"✅ ParamSpider complete for {target}.", "dim green")
        else:
            self.log("⚠️ ParamSpider not found.", "dim red")

    def run_arjun(self, start_pct=0, end_pct=100, custom_target=None):
        target = custom_target or f"https://{self.target}"
        if not self.is_dependency_met("arjun"): return
        self.log(f"🏹 Finding hidden parameters with Arjun on {target}...", "yellow")
        target_quoted = shlex.quote(target)
        cmd = f"arjun -u {target_quoted} -silent -t 50"
        output = self.run_cmd(cmd, start_pct=start_pct, end_pct=end_pct, timeout=300, capture_output=True)
        
        # Parse Arjun output for parameters and associate with URL
        import re
        found_any = False
        param_pattern = re.compile(r"parameter:\s*(\w+)", re.IGNORECASE)
        found_pattern = re.compile(r"found:\s*(\w+)", re.IGNORECASE)

        for line in output:
            params_found = param_pattern.findall(line) + found_pattern.findall(line)
            if not params_found and "[?]" in line:
                # Fallback for some arjun formats
                parts = line.split()
                if len(parts) > 1: params_found = [parts[-1].strip()]

            for param in params_found:
                param = param.strip(",").strip(":").strip()
                if param:
                    found_any = True
                    with self.ui_lock:
                        if target not in self.url_to_params:
                            self.url_to_params[target] = set()
                        self.url_to_params[target].add(param)
                        
                        if param not in self._hidden_param_set:
                            self._hidden_param_set.add(param)
                            self.findings["hidden_params"].append(param)
                        if param not in self._param_set:
                            self._param_set.add(param)
                            self.findings["params"].append(param)
        
        if found_any:
            self.log(f"✅ Arjun discovered hidden parameters on {target}.", "green")
        else:
            self.log(f"🏹 Arjun finished on {target}.", "dim")

    def run_fuzzing(self):
        self.log("🧪 Engaging Professional 3-Stage XSS Fuzzing Engine...", "yellow")
        
        # Consolidate targets: URLs with visible or hidden parameters
        fuzz_targets = []
        for url, params in self.url_to_params.items():
            if params:
                fuzz_targets.append((url, list(params)))
        
        if not fuzz_targets and self.findings["urls"]:
             # Fallback if map is empty but URLs exist
             for url in self.findings["urls"]:
                 p_set = set()
                 if "?" in url:
                     p_pair_list = url.split("?", 1)[1].split("&")
                     for pair in p_pair_list:
                         if "=" in pair: p_set.add(pair.split("=", 1)[0])
                 if p_set:
                     fuzz_targets.append((url, list(p_set)))

        if not fuzz_targets:
            self.log("⚠️ No URLs with parameters found for fuzzing.", "red")
            return
        
        try:
            all_payloads = []
            if self.manual_payloads:
                self.log(f"💉 Using {len(self.manual_payloads)} manually entered payloads.", "cyan")
                all_payloads = [{"payload": p, "type": "Generic"} for p in self.manual_payloads]
            else:
                # Default to payloads.json if no custom path set
                payload_path = self.custom_payload_path or os.path.join("payloads", "payloads.json")
                if not os.path.exists(payload_path):
                    # Fallback to local file if path is relative
                    payload_path = os.path.join(os.path.dirname(__file__), payload_path)
                    
                # Try payloads.json as default
                if not os.path.exists(payload_path) and not self.custom_payload_path:
                    payload_path = os.path.join(os.path.dirname(__file__), "payloads", "payloads.json")

                if not os.path.exists(payload_path):
                    self.log(f"❌ Error: Required payload file '{payload_path}' not found.", "red")
                    return

                if payload_path.endswith(".json"):
                    with open(payload_path, "r") as f:
                        all_payloads = json.load(f)
                else:
                    # Text file fallback
                    with open(payload_path, "r") as f:
                        lines = f.readlines()
                        all_payloads = [{"payload": l.strip(), "type": "Generic"} for l in lines if l.strip()]
        except Exception as e:
            self.log(f"❌ Failed to load payloads: {str(e)}", "red")
            return

        # --- STAGE 1: REFLECTION IDENTIFICATION ---
        self.log(f"🔍 [STAGE 1] Identifying reflecting parameters...", "cyan")
        reflecting_inputs = self.perform_reflection_check(fuzz_targets)
        
        if not reflecting_inputs:
            self.log("ℹ️ No reflecting parameters detected. Skipping further testing.", "yellow")
            return

        # --- STAGE 2: CONTEXT DISCOVERY ---
        self.log(f"🔬 [STAGE 2] Analyzing injection contexts for {len(reflecting_inputs)} inputs...", "magenta")
        context_aware_inputs = self.perform_context_discovery(reflecting_inputs)

        # --- STAGE 3: TARGETED FUZZING ---
        self.log(f"🚀 [STAGE 3] Targeted Fuzzing on {len(context_aware_inputs)} inputs...", "green")
        self.perform_targeted_fuzzing(context_aware_inputs, all_payloads)

        self.log("✅ 3-Stage fuzzing scan completed.", "green")

    def perform_reflection_check(self, targets):
        """Stage 1: Detect if input reflects at all using unique markers."""
        reflecting = []
        import random
        import string
        
        def check_reflection(url_data):
            url, params = url_data
            base_url = url.split("?", 1)[0]
            current_params = self.get_url_params_dict(url)
            
            local_reflecting = []
            for p in params:
                marker = "REF" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
                test_params = current_params.copy()
                test_params[p] = marker
                
                try:
                    resp = self.session.get(base_url, params=test_params, timeout=5)
                    if marker in resp.text:
                        local_reflecting.append((url, p))
                except:
                    pass
            return local_reflecting

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(check_reflection, t) for t in targets]
            for future in concurrent.futures.as_completed(futures):
                reflecting.extend(future.result())
        
        return reflecting

    def perform_context_discovery(self, reflecting_inputs):
        """Stage 2: Determine where the input lands and what characters are allowed."""
        # Multi-char probe to test both context and filtration
        probe = "xssprobe'\"<>/;()"
        results = []
        
        def discover_context(input_data):
            url, param = input_data
            base_url = url.split("?", 1)[0]
            current_params = self.get_url_params_dict(url)
            current_params[param] = probe
            
            try:
                resp = self.session.get(base_url, params=current_params, timeout=5)
                body = resp.text
                soup = BeautifulSoup(body, 'lxml' if shutil.which("lxml") else 'html.parser')
                
                # Check which special chars survived un-encoded
                allowed_chars = []
                for char in ["<", ">", "'", "\"", "/", ";", "(", ")"]:
                    if char in body and probe.replace(char, "") not in body: # Rough check if the char is present in the context of the probe
                         # More accurate: check if the string "xssprobe...char...probe" is there
                         if probe in body: allowed_chars.append(char)
                
                # If the probe itself isn't full there, but parts are, character detection is tricky
                # Let's fallback to just checking if the char is in the body at all (risky but better than nothing)
                if not allowed_chars:
                    for char in ["<", ">", "'", "\"", "/", ";", "(", ")"]:
                         if char in body: allowed_chars.append(char)

                contexts = []
                
                # Use BeautifulSoup to find where the probe is
                # 1. Check for text nodes (HTML context)
                for text_node in soup.find_all(string=re.compile("xssprobe")):
                    contexts.append("HTML")
                    break
                
                # 2. Check for attributes
                for tag in soup.find_all():
                    for attr_name, attr_val in tag.attrs.items():
                        if isinstance(attr_val, list): attr_val = " ".join(attr_val)
                        if "xssprobe" in attr_val:
                            contexts.append("Attribute")
                            break
                
                # 3. Check for script tags
                for script in soup.find_all("script"):
                    if script.string and "xssprobe" in script.string:
                        contexts.append("JS")
                        break
                
                # 4. Check for comments
                from bs4 import Comment
                for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                    if "xssprobe" in comment:
                        contexts.append("Comment")
                        break

                if not contexts: contexts.append("Generic")
                return (url, param, list(set(contexts)), allowed_chars)
            except Exception as e:
                return (url, param, ["Generic"], [])

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(discover_context, i) for i in reflecting_inputs]
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    self.log(f"Error in context discovery: {str(e)}", "red")
        return results

    def perform_targeted_fuzzing(self, context_inputs, payloads):
        """Stage 3: Run filtered payloads based on discovered context and allowed characters."""
        total_tasks = sum(len(payloads) for _ in context_inputs)
        self.task_total = total_tasks
        self.task_completed = 0
        
        def test_worker(input_context, payload_obj):
            url, param, contexts, allowed_chars = input_context
            p_val = payload_obj["payload"]
            p_type = payload_obj["type"] # e.g., "HTML", "Attribute", "JS"
            
            # 1. Context Matching
            should_run = False
            if p_type == "Generic" or p_type == "Basic":
                should_run = True
            elif any(c in p_type for c in contexts):
                should_run = True
            
            # 2. Filtration Matching (Advanced)
            # If the payload requires certain chars that we know are blocked, skip it
            required_chars = []
            if "<" in p_val: required_chars.append("<")
            if ">" in p_val: required_chars.append(">")
            if "'" in p_val: required_chars.append("'")
            if "\"" in p_val: required_chars.append("\"")
            
            if allowed_chars: # Only filter if we actually detected allowed chars
                for rc in required_chars:
                    if rc not in allowed_chars:
                        should_run = False
                        break

            if not should_run:
                with self.ui_lock: self.task_completed += 1
                return None

            base_url = url.split("?", 1)[0]
            test_params = self.get_url_params_dict(url)
            test_params[param] = p_val
            
            try:
                resp = self.session.get(base_url, params=test_params, timeout=5)
                # Confirmed if the payload reflects AND special symbols are intact
                if p_val in resp.text:
                    res = {
                        "type": f"XSS ({p_type})",
                        "url": base_url,
                        "param": param,
                        "payload": p_val,
                        "confidence": "HIGH" if p_type != "Generic" else "MEDIUM",
                        "context": ", ".join(contexts)
                    }
                    with self.ui_lock: self.task_completed += 1
                    return res
            except Exception as e:
                pass
            
            with self.ui_lock: self.task_completed += 1
            return None

        # Limit concurrent fuzzing to avoid crashing/WAF
        max_fuzz_workers = 30 if not self.waf_enabled else 10
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_fuzz_workers) as executor:
            futures = []
            # Batching to avoid memory issues with huge payload lists
            for inp in context_inputs:
                for p in payloads:
                    futures.append(executor.submit(test_worker, inp, p))
                    if len(futures) > 5000: # Process in chunks if extremely large
                        for future in concurrent.futures.as_completed(futures):
                            try:
                                result = future.result()
                                if result:
                                    with self.ui_lock:
                                        exists = any(v['url'] == result['url'] and v['param'] == result['param'] and v['payload'] == result['payload'] for v in self.findings["vulnerabilities"])
                                        if not exists:
                                            self.findings["vulnerabilities"].append(result)
                                            self.log(f"💥 [CONFIRMED] VULNERABILITY FOUND: {result['url']} [{result['param']}]", "bold red")
                                            self.update_ui()
                            except: pass
                        futures = []
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self.ui_lock:
                            exists = any(v['url'] == result['url'] and v['param'] == result['param'] and v['payload'] == result['payload'] for v in self.findings["vulnerabilities"])
                            if not exists:
                                self.findings["vulnerabilities"].append(result)
                                self.log(f"💥 [CONFIRMED] VULNERABILITY FOUND: {result['url']} [{result['param']}]", "bold red")
                                self.update_ui()
                except Exception as e:
                    self.log(f"Error in fuzzing worker: {str(e)}", "red")

    def get_url_params_dict(self, url):
        params_dict = {}
        if "?" in url:
            parts = url.split("?", 1)[1].split("&")
            for part in parts:
                if "=" in part:
                    k, v = part.split("=", 1)
                    params_dict[k] = v
        return params_dict

    def run_full_auto(self):
        self.log("🔥 STARTING HIGH-SPEED CONCURRENT HUNT...", "bold red")
        self.log("Initializing Discovery Module...", "cyan")
        self.scan_start = time.time()
        self.scan_completed = False
        self.total_progress = 0
        
        # Phase 1: Rapid Asset Discovery (Parallel)
        self.step_name = "Discovery & Harvesting"
        self.current_module = "Subfinder + GAU/Wayback (1/3)"
        self.log("Phase 1: Starting Parallel Discovery (Subfinder/GAU/Wayback)...", "cyan")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Run Subfinder, GAU, and Wayback simultaneously
            f1 = executor.submit(self.run_subfinder, 0, 100)
            f2 = executor.submit(self.run_gau_wayback, 0, 100)
            concurrent.futures.wait([f1, f2], timeout=300)

        self.total_progress = 30
        self.update_ui()

        # Phase 2: Mass Verification & Parameter Mining (Parallel)
        self.step_name = "Active Mining & Verification"
        self.current_module = "HTTPX + Katana + Arjun (2/3)"
        
        # Verify hosts found so far
        self.run_httpx(0, 50)
        
        live_hosts = self.findings["live_hosts"]
        if not live_hosts:
            live_hosts = [f"https://{self.target}"]

        top_targets = live_hosts[:10] # Scale up a bit but keep it fast
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for host in top_targets:
                futures.append(executor.submit(self.run_katana_hakrawler, 50, 80, host))
                futures.append(executor.submit(self.run_arjun, 80, 100, host))
            
            concurrent.futures.wait(futures, timeout=600)

        self.total_progress = 70
        self.update_ui()
        
        # Phase 3: Targeted Fuzzing
        self.step_name = "Precision XSS Fuzzing"
        self.current_module = "Fuzzing Engine (3/3)"
        self.step_progress = 0
        self.run_fuzzing()
        
        self.total_progress = 100
        self.step_progress = 100
        self.step_name = "COMPLETE"
        self.scan_completed = True
        self.update_ui()
        self.log("🏁 HIGH-SPEED HUNT COMPLETED!", "bold green")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEON_VOID: High-Tech XSS Recon & Fuzzing Tool")
    parser.add_argument("-t", "--target", help="Target domain (e.g., example.com)")
    parser.add_argument("-p", "--payloads", help="Path to custom payloads file (JSON or TXT)")
    args = parser.parse_args()

    try:
        tool = XSSHuntingTool()
        if args.target:
            if args.target.startswith("http"):
                tool.findings["urls"].append(args.target)
                tool.extract_params_from_url(args.target)
                # Extract domain for other modules
                from urllib.parse import urlparse
                tool.target = urlparse(args.target).netloc
            else:
                tool.target = args.target
        if args.payloads:
            tool.custom_payload_path = args.payloads
            
        tool.run()
    except KeyboardInterrupt:
        sys.exit(0)
