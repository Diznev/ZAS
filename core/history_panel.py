"""Target cards and saved-result timeline, independent of active scanning."""

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.gui_config import COLORS
from core.report_history import HISTORY_NOTE, build_target_history


class TargetHistoryPanel(tk.Frame):
    PAGE_SIZE = 200

    def __init__(self, parent, reports_dir, on_compare):
        super().__init__(parent, bg=COLORS["bg"])
        self.reports_dir = reports_dir
        self.on_compare = on_compare
        self.history = None
        self._busy = False
        self._closed = False
        self._events = queue.Queue()
        self._targets = []
        self._target_page = 0
        self._timeline = []
        self._timeline_page = 0
        self._selected = None
        self._build_ui()
        self.bind("<Destroy>", self._on_destroy, add="+")
        self._poll_id = self.after(100, self._poll)

    def _build_ui(self):
        tk.Label(self, text="Target history", font=("Consolas", 12, "bold"),
                 bg=COLORS["bg"], fg=COLORS["accent"]).pack(anchor="w", pady=(0, 8))
        ttk.Label(self, text=HISTORY_NOTE, wraplength=650, justify="left").pack(fill="x", pady=(0, 8))
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=4)
        self.refresh_button = ttk.Button(toolbar, text="Refresh history", command=self.refresh)
        self.refresh_button.pack(side="left")
        self.folder_button = ttk.Button(toolbar, text="Report directory...", command=self._choose_folder)
        self.folder_button.pack(side="left", padx=6)
        self.errors_button = ttk.Button(toolbar, text="Skipped files and errors", command=self._show_errors, state="disabled")
        self.errors_button.pack(side="left")
        self.directory_var = tk.StringVar(value=self.reports_dir)
        ttk.Label(self, textvariable=self.directory_var, wraplength=650).pack(fill="x")
        self.summary = tk.StringVar(value="Open history to load saved reports.")
        ttk.Label(self, textvariable=self.summary, wraplength=650).pack(fill="x", pady=6)
        search = ttk.Frame(self)
        search.pack(fill="x")
        ttk.Label(search, text="Find target").pack(side="left", padx=(0, 6))
        self.search_var = tk.StringVar()
        ttk.Entry(search, textvariable=self.search_var).pack(side="left", fill="x", expand=True)
        self.search_var.trace_add("write", lambda *_: self._filter_targets())
        self.targets_tree = self._table(self, ("url", "runs", "findings"),
                                        ("Target", "Reports", "Historical findings"), (450, 80, 150), height=5)
        self.targets_tree.bind("<<TreeviewSelect>>", self._select_target)
        target_pager = ttk.Frame(self)
        target_pager.pack(fill="x")
        self.target_previous = ttk.Button(target_pager, text="←", width=4, command=lambda: self._turn_targets(-1))
        self.target_previous.pack(side="left")
        self.target_page_var = tk.StringVar()
        ttk.Label(target_pager, textvariable=self.target_page_var).pack(side="left", padx=8)
        self.target_next = ttk.Button(target_pager, text="→", width=4, command=lambda: self._turn_targets(1))
        self.target_next.pack(side="left")
        self.card = tk.StringVar(value="Select a target in the table.")
        ttk.Label(self, textvariable=self.card, wraplength=650, justify="left").pack(fill="x", pady=8)
        self.compare_button = ttk.Button(self, text="Compare this target's two latest reports",
                                          command=self._compare_latest, state="disabled")
        self.compare_button.pack(anchor="w")
        self.timeline_tree = self._table(self, ("date", "cve", "status", "method", "report"),
                                         ("Saved (UTC)", "CVE / ID", "Statuses", "Methods", "Report"),
                                         (180, 160, 120, 220, 220), height=8, expand=True)
        timeline_pager = ttk.Frame(self)
        timeline_pager.pack(fill="x")
        self.timeline_previous = ttk.Button(timeline_pager, text="← Previous", command=lambda: self._turn_timeline(-1))
        self.timeline_previous.pack(side="left")
        self.timeline_page_var = tk.StringVar()
        ttk.Label(timeline_pager, textvariable=self.timeline_page_var).pack(side="left", padx=8)
        self.timeline_next = ttk.Button(timeline_pager, text="Next →", command=lambda: self._turn_timeline(1))
        self.timeline_next.pack(side="left")
        self._render_targets()
        self._render_timeline()

    @staticmethod
    def _table(parent, columns, titles, widths, height, expand=False):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=expand, pady=6)
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=height, selectmode="browse")
        for key, title, width in zip(columns, titles, widths):
            tree.heading(key, text=title)
            tree.column(key, width=width, minwidth=60)
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        return tree

    def _choose_folder(self):
        directory = filedialog.askdirectory(parent=self, title="ZAS report directory", initialdir=self.reports_dir)
        if directory:
            self.reports_dir = directory
            self.directory_var.set(directory)
            self.refresh()

    def refresh(self):
        if self._busy or self._closed:
            return
        directory = self.reports_dir
        self._busy = True
        self.history = None
        self._filter_targets()
        self.summary.set("Loading history...")
        for button in (self.refresh_button, self.folder_button, self.errors_button):
            button.configure(state="disabled")

        def read():
            try:
                self._events.put((build_target_history(directory), None))
            except (OSError, ValueError, RecursionError) as exc:
                self._events.put((None, str(exc)))

        threading.Thread(target=read, daemon=True, name="zas-target-history").start()

    def _poll(self):
        if self._closed:
            return
        try:
            result, error = self._events.get_nowait()
        except queue.Empty:
            pass
        else:
            self._busy = False
            self.refresh_button.configure(state="normal")
            self.folder_button.configure(state="normal")
            self.history = result
            if error:
                self.summary.set("Could not load history.")
                messagebox.showerror("ZAS — history", error, parent=self)
            else:
                suffix = " · Partial history: limit reached" if result["limited"] else ""
                self.summary.set(f"Targets: {len(result['targets'])} · Reports: {result['loaded_reports']} · "
                                 f"Skipped/errors: {len(result['errors'])}{suffix}")
                self.errors_button.configure(state="normal" if result["errors"] or result["limited"] else "disabled")
            self._filter_targets()
        self._poll_id = self.after(100, self._poll)

    def _filter_targets(self):
        query = self.search_var.get().strip().casefold()
        self._targets = [target for target in (self.history["targets"] if self.history else [])
                         if not query or query in target["url"].casefold()]
        self._target_page = 0
        self._render_targets()

    def _render_targets(self):
        children = self.targets_tree.get_children()
        if children:
            self.targets_tree.delete(*children)
        start = self._target_page * self.PAGE_SIZE
        for index, target in enumerate(self._targets[start:start + self.PAGE_SIZE], start):
            self.targets_tree.insert("", "end", iid=str(index), values=(target["url"], target["report_count"], target["unique_findings"]))
        pages = max(1, (len(self._targets) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self.target_page_var.set(f"Targets: {len(self._targets)} · {self._target_page + 1}/{pages}")
        self.target_previous.configure(state="normal" if self._target_page else "disabled")
        self.target_next.configure(state="normal" if self._target_page + 1 < pages else "disabled")
        self._selected = None
        self._timeline = []
        self._timeline_page = 0
        self.card.set("Select a target in the table.")
        self.compare_button.configure(state="disabled")
        # The timeline is built after the first target render during setup.
        if hasattr(self, "timeline_tree"):
            self._render_timeline()

    def _select_target(self, event=None):
        selection = self.targets_tree.selection()
        if not selection:
            return
        index = int(selection[0])
        if index >= len(self._targets):
            return
        self._selected = self._targets[index]
        target = self._selected
        latest = target["runs"][0]
        self.card.set(f"{target['url']}\nReports: {target['report_count']} · "
                      f"Unique historical findings: {target['unique_findings']}\n"
                      f"Latest saved report: {target['latest_saved_at']} · "
                      f"Findings in that report: {latest['positive_findings']}")
        self._timeline = [(run, row) for run in target["runs"] for row in run["findings"]]
        self._timeline_page = 0
        self._render_timeline()
        self.compare_button.configure(state="normal" if len(target["runs"]) >= 2 else "disabled")

    def _render_timeline(self):
        children = self.timeline_tree.get_children()
        if children:
            self.timeline_tree.delete(*children)
        start = self._timeline_page * self.PAGE_SIZE
        for run, row in self._timeline[start:start + self.PAGE_SIZE]:
            self.timeline_tree.insert("", "end", values=(run["saved_at"], row["cve"],
                                      ", ".join(row["statuses"]), ", ".join(row["methods"]) or "Not specified", run["report"]))
        pages = max(1, (len(self._timeline) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self.timeline_page_var.set(f"Entries: {len(self._timeline)} · {self._timeline_page + 1}/{pages}")
        self.timeline_previous.configure(state="normal" if self._timeline_page else "disabled")
        self.timeline_next.configure(state="normal" if self._timeline_page + 1 < pages else "disabled")

    def _turn_targets(self, direction):
        pages = max(1, (len(self._targets) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self._target_page = max(0, min(pages - 1, self._target_page + direction))
        self._render_targets()

    def _turn_timeline(self, direction):
        pages = max(1, (len(self._timeline) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self._timeline_page = max(0, min(pages - 1, self._timeline_page + direction))
        self._render_timeline()

    def _compare_latest(self):
        if self._selected and len(self._selected["runs"]) >= 2:
            newest, previous = self._selected["runs"][:2]
            self.on_compare(previous["path"], newest["path"], self._selected["id"], self._selected["url"])

    def _show_errors(self):
        if self.history:
            lines = [f"{item['file']}: {item['reason']}" for item in self.history["errors"][:30]]
            if self.history["limited"]:
                lines.insert(0, "History limits: 200 reports, 100,000 records and 64 MiB total; only the selected directory and its immediate subdirectories are searched.")
            if len(self.history["errors"]) > 30:
                lines.append(f"More errors: {len(self.history['errors']) - 30}")
            messagebox.showinfo("ZAS — skipped history files", "\n".join(lines), parent=self)

    def _on_destroy(self, event):
        if event.widget is self:
            self._closed = True
            self.after_cancel(self._poll_id)
