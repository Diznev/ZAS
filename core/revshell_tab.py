"""Reverse-shell listener panel for the ZAS GUI.

A dark-themed tkinter panel that owns a ``zas_listener.ReverseListener``
and a ``zas_revshell`` payload generator. Deliberately independent of
``ShellTab``: that class drives an HTTP webshell (``?t=token&c=cmd``),
while this one is a raw TCP stream — different interaction model.

Callbacks from the listener arrive on worker threads; everything that
touches widgets is marshalled through ``widget.after(0, ...)``.
"""

from __future__ import annotations

import queue
import tkinter as tk
from tkinter import ttk, scrolledtext

from zas_listener import ReverseListener
import zas_revshell

BG = "#0a0d0b"
BG2 = "#080a08"
FG = "#c9d1d9"
ACCENT = "#c9ff45"
MUTED = "#8b949e"
RED = "#f85149"
BORDER = "#21262d"

MONO = ("Consolas", 9)
MONO_LG = ("Consolas", 10)
UI = ("Segoe UI", 9)
UI_BOLD = ("Segoe UI", 9, "bold")


class RevShellPanel(tk.Frame):
    """Listener controls + payload generator + interactive console."""

    def __init__(self, parent, default_host="", default_port=4444, **kw):
        super().__init__(parent, bg=BG, **kw)
        self.default_host = default_host
        self.listener = None
        self.active_client = None
        # tkinter's after() is not safe to call from the listener's worker
        # threads, so everything they want the UI to do goes through this
        # queue and is drained on the main thread by _poll().
        self._q = queue.Queue()
        self._closing = False

        self._build_header(default_host, default_port)
        self._build_payload_bar()
        self._build_console()
        self._build_input()
        self._poll()

    # -- UI construction ----------------------------------------------

    def _build_header(self, host, port):
        bar = tk.Frame(self, bg=BG, pady=8, padx=10)
        bar.pack(fill="x")

        tk.Label(bar, text="LISTENER", font=UI_BOLD, bg=BG, fg=ACCENT
                 ).pack(side="left")

        tk.Label(bar, text="Host", font=UI, bg=BG, fg=MUTED).pack(side="left", padx=(14, 4))
        self.host_var = tk.StringVar(value=host or "0.0.0.0")
        tk.Entry(bar, textvariable=self.host_var, width=14, font=MONO,
                 bg=BG2, fg=FG, insertbackground=FG, relief="flat"
                 ).pack(side="left")

        tk.Label(bar, text="Port", font=UI, bg=BG, fg=MUTED).pack(side="left", padx=(10, 4))
        self.port_var = tk.StringVar(value=str(port))
        tk.Entry(bar, textvariable=self.port_var, width=7, font=MONO,
                 bg=BG2, fg=FG, insertbackground=FG, relief="flat"
                 ).pack(side="left")

        self.toggle_btn = tk.Button(
            bar, text="▶ START", font=UI_BOLD, bg=ACCENT, fg="#000",
            activebackground=ACCENT, relief="flat", padx=14, pady=3,
            command=self.toggle,
        )
        self.toggle_btn.pack(side="left", padx=(14, 8))

        self.status_lbl = tk.Label(bar, text="● stopped", font=MONO,
                                   bg=BG, fg=MUTED)
        self.status_lbl.pack(side="left", padx=6)

        self.clients_lbl = tk.Label(bar, text="clients: 0", font=MONO,
                                    bg=BG, fg=MUTED)
        self.clients_lbl.pack(side="right")

    def _build_payload_bar(self):
        bar = tk.Frame(self, bg=BG, pady=4, padx=10)
        bar.pack(fill="x")

        tk.Label(bar, text="PAYLOAD", font=UI_BOLD, bg=BG, fg=ACCENT).pack(side="left")

        self.lang_var = tk.StringVar(value="bash")
        langs = list(zas_revshell.LANGS) + ["auto"]
        box = ttk.Combobox(bar, textvariable=self.lang_var, values=langs,
                           width=12, state="readonly")
        box.pack(side="left", padx=(12, 8))
        box.bind("<<ComboboxSelected>>", lambda e: self._refresh_payload())

        self.payload_var = tk.StringVar()
        tk.Entry(bar, textvariable=self.payload_var, font=MONO, bg=BG2,
                 fg=FG, insertbackground=FG, relief="flat"
                 ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        tk.Button(bar, text="Copy", font=UI, bg=BG2, fg=FG, relief="flat",
                  padx=10, command=self._copy_payload).pack(side="left")

    def _build_console(self):
        wrap = tk.Frame(self, bg=BORDER, padx=1, pady=1)
        wrap.pack(fill="both", expand=True, padx=10, pady=(6, 4))
        self.console = scrolledtext.ScrolledText(
            wrap, bg=BG2, fg=ACCENT, font=MONO, relief="flat",
            insertbackground=FG, wrap="word", height=16,
        )
        self.console.pack(fill="both", expand=True)
        self.console.configure(state="disabled")

    def _build_input(self):
        bar = tk.Frame(self, bg=BG, pady=8, padx=10)
        bar.pack(fill="x")

        tk.Label(bar, text="$", font=("Consolas", 12, "bold"),
                 bg=BG, fg=ACCENT).pack(side="left", padx=(0, 6))

        self.cmd_var = tk.StringVar()
        entry = tk.Entry(bar, textvariable=self.cmd_var, font=MONO_LG,
                         bg=BG2, fg=FG, insertbackground=FG, relief="flat")
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self._send_cmd())
        self.cmd_entry = entry

        tk.Button(bar, text="Send", font=UI_BOLD, bg=BG2, fg=FG,
                  relief="flat", padx=12, command=self._send_cmd
                  ).pack(side="left", padx=(8, 0))

        self.target_var = tk.StringVar(value="all")
        ttk.Combobox(bar, textvariable=self.target_var, width=10,
                     values=["all"], state="readonly").pack(side="left", padx=(8, 0))

    # -- payload ------------------------------------------------------

    def _refresh_payload(self):
        host = self.host_var.get().strip() or "127.0.0.1"
        try:
            port = int(self.port_var.get())
        except ValueError:
            port = 4444
        lang = self.lang_var.get()
        try:
            if lang == "auto":
                txt = zas_revshell.auto_payload(host, port)
            else:
                txt = zas_revshell.payload(host, port, lang)
        except ValueError as e:
            txt = "# %s" % e
        self.payload_var.set(txt)

    def _copy_payload(self):
        txt = self.payload_var.get()
        if not txt:
            return
        self.clipboard_clear()
        self.clipboard_append(txt)
        self._log("[payload copied to clipboard]")

    # -- listener control --------------------------------------------

    def toggle(self):
        if self.listener is not None and self.listener.running:
            self.stop()
        else:
            self.start()

    def start(self):
        try:
            host = self.host_var.get().strip() or "0.0.0.0"
            port = int(self.port_var.get())
        except ValueError:
            self._log("[!] port must be a number", err=True)
            return

        lst = ReverseListener(
            host=host, port=port,
            on_connect=self._on_connect,
            on_data=self._on_data,
            on_close=self._on_close,
            on_error=lambda e: self._log("[listener error] %s" % e, err=True),
        )
        try:
            bound = lst.start()
        except OSError as e:
            self._log("[!] cannot bind %s:%d — %s" % (host, port, e), err=True)
            return

        self.listener = lst
        self.toggle_btn.configure(text="■ STOP", bg=RED)
        self._set_status("listening on %s:%d" % (host, bound), ACCENT)
        self._log("[+] listening on %s:%d" % (host, bound))
        self._refresh_payload()

    def stop(self):
        if self.listener is None:
            return
        self.listener.stop()
        self.listener = None
        self.active_client = None
        self.toggle_btn.configure(text="▶ START", bg=ACCENT)
        self._set_status("● stopped", MUTED)
        self._log("[*] listener stopped")
        self._refresh_clients()

    # -- listener callbacks (worker threads) -------------------------

    def _on_connect(self, client):
        self.active_client = client
        self._log("[+] shell from %s:%d" % client.addr)
        self._refresh_clients()

    def _on_data(self, client, text):
        self._log(text, raw=True)

    def _on_close(self, client):
        self._log("[*] %s:%d closed" % client.addr)
        self._refresh_clients()

    # -- interaction -------------------------------------------------

    def _send_cmd(self):
        cmd = self.cmd_var.get()
        if not cmd:
            return
        if self.listener is None or self.listener.client_count() == 0:
            self._log("[!] no connected shell", err=True)
            return
        target = self.target_var.get()
        client = None if target == "all" else self.active_client
        n = self.listener.send(cmd + "\n", client=client)
        self._log("$ %s   [%d client%s]" % (cmd, n, "" if n == 1 else "s"))
        self.cmd_var.set("")

    # -- helpers (all marshal to the UI thread) -----------------------

    def _log(self, msg, err=False, raw=False):
        def append():
            self.console.configure(state="normal")
            if raw:
                self.console.insert("end", msg)
            else:
                self.console.insert("end", msg + "\n")
            if err:
                # colour the last line
                idx = self.console.index("end-2l linestart")
                self.console.tag_add("err", idx, "end-1c")
                self.console.tag_configure("err", foreground=RED)
            self.console.see("end")
            self.console.configure(state="disabled")
        self._ui(append)

    def _set_status(self, text, colour):
        def setit():
            self.status_lbl.configure(text=text, fg=colour)
        self._ui(setit)

    def _refresh_clients(self):
        def setit():
            self.clients_lbl.configure(
                text="clients: %d" % (self.listener.client_count()
                                      if self.listener else 0))
            vals = ["all"] + ["%s:%d" % c.addr for c in
                              (self.listener.clients if self.listener else [])]
            for child in self.winfo_children():
                self._update_combobox(child, vals)
        self._ui(setit)

    def _update_combobox(self, widget, values):
        if isinstance(widget, ttk.Combobox) and str(widget.cget("textvariable")) == str(self.target_var):
            widget.configure(values=values)
        for child in widget.winfo_children():
            self._update_combobox(child, values)

    def _ui(self, fn):
        """Queue ``fn`` to run on the main thread.

        Safe to call from any thread. Used by the listener callbacks;
        direct UI-thread callers go through it too so there is one path.
        """
        if self._closing:
            return
        self._q.put(fn)

    def _poll(self):
        """Drain queued UI work. Reschedules itself until destroyed."""
        if self._closing:
            return
        try:
            while True:
                fn = self._q.get_nowait()
                try:
                    fn()
                except Exception:
                    pass
        except queue.Empty:
            pass
        if not self._closing:
            try:
                self.after(50, self._poll)
            except Exception:
                self._closing = True

    def destroy(self):
        self._closing = True
        self.stop()
        super().destroy()
