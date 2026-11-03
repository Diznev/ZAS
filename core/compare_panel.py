"""Tk panel for offline comparison of two saved audit reports."""

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.gui_config import COLORS
from core.report_comparison import (
    CHANGE_LABELS, COMPARISON_NOTE, compare_reports, generate_comparison_html, load_report,
)


class ReportComparisonPanel(tk.Frame):
    PAGE_SIZE = 200

    def __init__(self, parent, reports_dir):
        super().__init__(parent, bg=COLORS["bg"])
        self.reports_dir = reports_dir
        self.comparison = None
        self._events = queue.Queue()
        self._busy = False
        self._closed = False
        self._page = 0
        self._filtered = []
        self._target_id = None
        self._build_ui()
        self.bind("<Destroy>", self._on_destroy, add="+")
        self._poll_id = self.after(100, self._poll)

    def _build_ui(self):
        tk.Label(self, text="Audit comparison", bg=COLORS["bg"], fg=COLORS["accent"],
                 font=("Consolas", 12, "bold")).pack(anchor="w", pady=(0, 8))
        tk.Label(self, text=COMPARISON_NOTE, bg=COLORS["bg"], fg=COLORS["fg2"],
                 justify="left", wraplength=650).pack(fill="x", pady=(0, 12))
        self.paths = [tk.StringVar(), tk.StringVar()]
        self._load_buttons = []
        for index, label in enumerate(("Previous report", "Current report")):
            row = ttk.Frame(self)
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=label, width=19).pack(side="left")
            ttk.Entry(row, textvariable=self.paths[index], state="readonly").pack(side="left", fill="x", expand=True)
            button = ttk.Button(row, text="Choose JSON", command=lambda i=index: self._choose(i))
            button.pack(side="left", padx=(6, 0))
            self._load_buttons.append(button)
        controls = ttk.Frame(self)
        controls.pack(fill="x", pady=10)
        self.compare_button = ttk.Button(controls, text="Compare", command=self._start_comparison)
        self.compare_button.pack(side="left")
        self.export_button = ttk.Button(controls, text="Save HTML", command=self._export, state="disabled")
        self.export_button.pack(side="left", padx=8)
        ttk.Button(controls, text="All targets", command=self._clear_scope).pack(side="left")
        self.scope_var = tk.StringVar(value="All targets in the selected reports")
        ttk.Label(self, textvariable=self.scope_var, wraplength=650).pack(fill="x", pady=(0, 6))
        self.summary = tk.StringVar(value="Choose two ZAS JSON reports.")
        ttk.Label(self, textvariable=self.summary, wraplength=650).pack(fill="x", pady=(0, 8))
        filters = ttk.Frame(self)
        filters.pack(fill="x", pady=(0, 8))
        self.filter_var = tk.StringVar(value="All changes")
        choices = ["All changes"] + list(CHANGE_LABELS.values())
        ttk.Label(filters, text="Changes:").pack(side="left", padx=(0, 6))
        selector = ttk.Combobox(filters, textvariable=self.filter_var, values=choices,
                                state="readonly", width=30)
        selector.pack(side="left")
        selector.bind("<<ComboboxSelected>>", lambda event: self._filter_rows())
        self.search_var = tk.StringVar()
        ttk.Entry(filters, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=(8, 0))
        self.search_var.trace_add("write", lambda *_: self._filter_rows())
        ttk.Label(self, text="Search by CVE or target. Export includes all comparison rows.").pack(anchor="w")
        table = ttk.Frame(self)
        table.pack(fill="both", expand=True, pady=6)
        columns = ("change", "cve", "url", "before", "after")
        self.tree = ttk.Treeview(table, columns=columns, show="headings", height=16)
        for key, title, width in zip(columns, ("Change", "CVE / ID", "Target", "Before", "After"), (180, 150, 250, 100, 100)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, minwidth=80)
        vertical = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        pager = ttk.Frame(self)
        pager.pack(fill="x")
        self.previous_button = ttk.Button(pager, text="← Previous", command=lambda: self._turn_page(-1), state="disabled")
        self.previous_button.pack(side="left")
        self.page_text = tk.StringVar(value="No results")
        ttk.Label(pager, textvariable=self.page_text).pack(side="left", padx=10)
        self.next_button = ttk.Button(pager, text="Next →", command=lambda: self._turn_page(1), state="disabled")
        self.next_button.pack(side="left")

    def _choose(self, index):
        path = filedialog.askopenfilename(parent=self, title="ZAS JSON report",
                                          initialdir=self.reports_dir, filetypes=[("ZAS JSON", "*.json")])
        if not path:
            return
        self.paths[index].set(path)
        self._target_id = None
        self.scope_var.set("All targets in the selected reports")
        self.comparison = None
        self.export_button.configure(state="disabled")
        self.summary.set("Report changed. Click Compare.")
        self._filter_rows()

    def set_reports(self, baseline, current, target_id=None, target_label=""):
        """Open a pair from history, optionally scoped to one endpoint."""
        if self._busy:
            messagebox.showinfo("ZAS", "Wait for the current comparison to finish.", parent=self)
            return False
        self.paths[0].set(baseline)
        self.paths[1].set(current)
        self._target_id = target_id
        self.scope_var.set(f"Target only: {target_label}" if target_id else "All targets in the selected reports")
        self.filter_var.set("All changes")
        self.search_var.set("")
        self._start_comparison()
        return True

    def _clear_scope(self):
        if self._busy or self._target_id is None:
            return
        self._target_id = None
        self.scope_var.set("All targets in the selected reports")
        self.comparison = None
        self.export_button.configure(state="disabled")
        self.summary.set("All targets selected. Click Compare.")
        self._filter_rows()

    def _start_comparison(self):
        if self._busy:
            return
        paths = [value.get() for value in self.paths]
        if not all(paths):
            messagebox.showinfo("ZAS", "Choose the previous and current JSON reports.", parent=self)
            return
        self._busy = True
        self.comparison = None
        self._filter_rows()
        self.export_button.configure(state="disabled")
        for button in self._load_buttons + [self.compare_button]:
            button.configure(state="disabled")
        self.summary.set("Loading and comparing reports...")
        target_id = self._target_id

        def run():
            try:
                result = compare_reports(load_report(paths[0]), load_report(paths[1]), target_id=target_id)
                self._events.put((result, None))
            except (OSError, ValueError, RecursionError) as exc:
                self._events.put((None, str(exc)))

        threading.Thread(target=run, daemon=True, name="zas-report-comparison").start()

    def _poll(self):
        if self._closed:
            return
        try:
            result, error = self._events.get_nowait()
        except queue.Empty:
            pass
        else:
            self._busy = False
            for button in self._load_buttons + [self.compare_button]:
                button.configure(state="normal")
            self.comparison = result
            if error:
                self.summary.set("Could not compare reports.")
                messagebox.showerror("ZAS — comparison", error, parent=self)
            else:
                counts = result["counts"]
                self.summary.set(f"New: {counts['new']} · Repeated: {counts['repeated']} · "
                                 f"Not reconfirmed: {counts['not_reconfirmed']}")
                self.export_button.configure(state="normal")
            self._filter_rows()
        self._poll_id = self.after(100, self._poll)

    def _filter_rows(self):
        rows = self.comparison["rows"] if self.comparison else []
        selected = self.filter_var.get()
        query = self.search_var.get().strip().casefold()
        self._filtered = [row for row in rows
                          if (selected == "All changes" or CHANGE_LABELS[row["change"]] == selected)
                          and (not query or query in (row["cve"] + " " + row["url"]).casefold())]
        self._page = 0
        self._render_page()

    def _turn_page(self, direction):
        pages = max(1, (len(self._filtered) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self._page = max(0, min(pages - 1, self._page + direction))
        self._render_page()

    def _render_page(self):
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        start = self._page * self.PAGE_SIZE
        for row in self._filtered[start:start + self.PAGE_SIZE]:
            self.tree.insert("", "end", values=(CHANGE_LABELS[row["change"]], row["cve"], row["url"],
                             ", ".join(row["baseline_statuses"]) or "No record",
                             ", ".join(row["current_statuses"]) or "No record"))
        pages = max(1, (len(self._filtered) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self.page_text.set(f"Page {self._page + 1}/{pages} · Rows: {len(self._filtered)}")
        self.previous_button.configure(state="normal" if self._page else "disabled")
        self.next_button.configure(state="normal" if self._page + 1 < pages else "disabled")

    def _export(self):
        if self.comparison is None or self._busy:
            return
        path = filedialog.asksaveasfilename(parent=self, title="Save comparison",
                                            initialdir=self.reports_dir, initialfile="zas_comparison.html",
                                            defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not path:
            return
        if os.path.normcase(os.path.realpath(path)) in {
            os.path.normcase(os.path.realpath(value.get())) for value in self.paths
        }:
            messagebox.showerror("ZAS", "Choose another file: source reports cannot be overwritten.", parent=self)
            return
        try:
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(generate_comparison_html(self.comparison))
        except OSError as exc:
            messagebox.showerror("ZAS", f"Could not save comparison: {exc}", parent=self)
            return
        self.summary.set(f"Comparison saved: {path}")

    def _on_destroy(self, event):
        if event.widget is self:
            self._closed = True
            self.after_cancel(self._poll_id)
