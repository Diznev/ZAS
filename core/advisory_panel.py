"""Preview advisory metadata and explicitly select cards for the local catalog."""

import queue
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk

from core.advisory_import import classify_preview


class AdvisoryImportDialog(tk.Toplevel):
    def __init__(self, parent, client, existing, modules, on_submit):
        super().__init__(parent)
        self.title("ZAS — fetch advisory metadata")
        self.geometry("1120x800")
        self.minsize(850, 650)
        self.transient(parent.winfo_toplevel())
        self.client = client
        self.existing = list(existing)
        self.modules = modules
        self.on_submit = on_submit
        self.items = []
        self.selected = set()
        self._busy = False
        self._saving = False
        self._closed = False
        self._events = queue.Queue()
        self._build_ui()
        self.bind("<Destroy>", self._on_destroy, add="+")
        self._poll_id = self.after(100, self._poll)
        self.grab_set()

    def _build_ui(self):
        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Fetch metadata, review sources and web scope, then add selected research cards. "
                              "No PoC code is downloaded, executed or installed.", wraplength=1030).pack(fill="x", pady=(0, 10))
        query = ttk.Frame(body)
        query.pack(fill="x")
        ttk.Label(query, text="Source:").pack(side="left", padx=(0, 6))
        self.provider_var = tk.StringVar(value="GHSA")
        self.provider_box = ttk.Combobox(query, textvariable=self.provider_var, values=["GHSA", "NVD"], state="readonly", width=10)
        self.provider_box.pack(side="left")
        ttk.Label(query, text="Query:").pack(side="left", padx=(10, 6))
        self.query_var = tk.StringVar()
        self.query_entry = ttk.Entry(query, textvariable=self.query_var)
        self.query_entry.pack(side="left", fill="x", expand=True)
        self.query_entry.bind("<Return>", lambda event: self._fetch())
        self.fetch_button = ttk.Button(query, text="Fetch metadata", command=self._fetch)
        self.fetch_button.pack(side="left", padx=(8, 0))
        ttk.Label(body, text="GHSA: CVE ID or exact package name; blank lists recently updated advisories. "
                              "NVD: CVE ID or keyword required. First API page only: up to 20 advisories and 40 cards.",
                  wraplength=1030).pack(fill="x", pady=8)
        self.summary = tk.StringVar(value="Nothing fetched. The catalog will change only after Add selected.")
        ttk.Label(body, textvariable=self.summary, wraplength=1030).pack(fill="x", pady=(0, 6))
        table = ttk.Frame(body)
        table.pack(fill="both", expand=True)
        columns = ("selected", "cve", "product", "versions", "poc", "match")
        self.tree = ttk.Treeview(table, columns=columns, show="headings", height=11, selectmode="browse")
        for key, title, width in zip(columns, ("Add", "CVE / ID", "Product", "Version claims", "PoC evidence", "Existing coverage"),
                                      (45, 155, 180, 210, 195, 250)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, minwidth=40)
        vertical = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self._details)
        self.tree.bind("<Double-1>", lambda event: self._toggle(self.tree.identify_row(event.y)))
        self.tree.bind("<space>", lambda event: self._toggle())
        ttk.Label(body, text="Double-click a row or press Space to toggle it. Select new skips catalog duplicates and module matches. "
                              "A tagged reference is not proof of a working PoC.", wraplength=1030).pack(fill="x", pady=6)
        self.details = scrolledtext.ScrolledText(body, height=10, wrap="word", state="disabled", font=("Consolas", 9))
        self.details.pack(fill="both", expand=True)
        actions = ttk.Frame(body)
        actions.pack(fill="x", pady=(10, 0))
        self.select_button = ttk.Button(actions, text="Select new", command=self._select_new, state="disabled")
        self.select_button.pack(side="left")
        self.clear_button = ttk.Button(actions, text="Clear selection", command=self._clear_selection, state="disabled")
        self.clear_button.pack(side="left", padx=6)
        self.save_button = ttk.Button(actions, text="Add selected (0)", command=self._submit, state="disabled")
        self.save_button.pack(side="right")
        ttk.Button(actions, text="Close", command=self.destroy).pack(side="right", padx=8)

    def _fetch(self):
        if self._busy or self._saving:
            return
        provider, query = self.provider_var.get(), self.query_var.get()
        self._busy = True
        self.items = []
        self.selected.clear()
        self._render()
        self.summary.set(f"Fetching public {provider} metadata...")
        self._update_controls()

        def work():
            try:
                self._events.put((self.client.fetch(provider, query), None))
            except (OSError, ValueError, RecursionError) as exc:
                self._events.put((None, str(exc)))

        threading.Thread(target=work, daemon=True, name="zas-advisory-fetch").start()

    def _poll(self):
        if self._closed:
            return
        try:
            result, error = self._events.get_nowait()
        except queue.Empty:
            pass
        else:
            self._busy = False
            if error:
                self.summary.set(error)
            else:
                self.items = classify_preview(result["items"], self.existing, self.modules)
                suffix = " More matches exist; refine the query." if result["more"] else ""
                self.summary.set(f"Cards: {len(self.items)} · Source records skipped: {result['skipped']} · "
                                 f"Fetched (UTC): {result['fetched_at']}.{suffix} Review before adding.")
                self._render()
            self._update_controls()
        self._poll_id = self.after(100, self._poll)

    def _render(self):
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        for index, item in enumerate(self.items):
            candidate = item["candidate"]
            self.tree.insert("", "end", iid=str(index), values=("✓" if index in self.selected else "",
                             candidate["cve"], candidate["product"], candidate["versions"] or "Not provided",
                             item["poc_status"], item["match"]))
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.configure(state="disabled")

    def _details(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        index = int(selection[0])
        if index >= len(self.items):
            return
        candidate = self.items[index]["candidate"]
        text = (f"{candidate['cve']} — {candidate['product']}\n"
                f"Advisory: {candidate['advisory_url']}\nResearch source: {candidate['poc_url']}\n"
                f"Versions (source claims): {candidate['versions'] or 'Not provided'}\n\n{candidate['notes']}")
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _toggle(self, iid=None):
        if self._busy or self._saving:
            return
        if not iid:
            selection = self.tree.selection()
            iid = selection[0] if selection else None
        if iid is None:
            return
        index = int(iid)
        if index >= len(self.items) or not self.items[index]["addable"]:
            return
        if index in self.selected:
            self.selected.remove(index)
        else:
            self.selected.add(index)
        self.tree.set(iid, "selected", "✓" if index in self.selected else "")
        self._update_controls()

    def _select_new(self):
        if self._busy or self._saving:
            return
        self.selected = {index for index, item in enumerate(self.items) if item["addable"] and item["match"] == "New"}
        self._render()
        self._update_controls()

    def _clear_selection(self):
        if not self._busy and not self._saving:
            self.selected.clear()
            self._render()
            self._update_controls()

    def _update_controls(self):
        blocked = self._busy or self._saving
        self.provider_box.configure(state="disabled" if blocked else "readonly")
        self.query_entry.configure(state="disabled" if blocked else "normal")
        self.fetch_button.configure(state="disabled" if blocked else "normal")
        for button in (self.select_button, self.clear_button):
            button.configure(state="normal" if self.items and not blocked else "disabled")
        self.save_button.configure(text=f"Add selected ({len(self.selected)})",
                                   state="normal" if self.selected and not blocked else "disabled")

    def _submit(self):
        if self._busy or self._saving or not self.selected:
            return
        records = [self.items[index]["candidate"] for index in sorted(self.selected) if self.items[index]["addable"]]
        self._saving = True
        self._update_controls()
        self.on_submit(records, self)

    def save_failed(self):
        self._saving = False
        self.summary.set("Import failed. Selection preserved. Reload the catalog if another window changed it.")
        self._update_controls()

    def _on_destroy(self, event):
        if event.widget is self:
            self._closed = True
            self.after_cancel(self._poll_id)
