"""Local CVE research queue with explicit workflow stages and source references."""

from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import webbrowser

from core.candidate_catalog import (
    CATALOG_NOTE, STATUSES, load_catalog, make_candidate, merge_candidates,
    save_catalog, validate_source_url,
)
from core.gui_config import COLORS
from core.advisory_import import AdvisoryClient
from core.advisory_panel import AdvisoryImportDialog


class CandidateEditor(tk.Toplevel):
    def __init__(self, parent, original, on_submit):
        super().__init__(parent)
        self.title("ZAS — CVE candidate")
        self.geometry("790x760")
        self.minsize(650, 650)
        self.transient(parent.winfo_toplevel())
        self.original = original
        self.on_submit = on_submit
        self.inputs = {}
        form = ttk.Frame(self, padding=12)
        form.pack(fill="both", expand=True)
        ttk.Label(form, text="The claimed CVE requires verification. Status indicates the research stage.", wraplength=710).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        fields = [
            ("cve", "CVE / CVE-UNVERIFIED"), ("product", "Product"),
            ("versions", "Affected versions"), ("poc_url", "Public PoC / research"),
            ("advisory_url", "Advisory"), ("revision", "Source revision / commit"),
        ]
        for index, (key, label) in enumerate(fields, 1):
            ttk.Label(form, text=label).grid(row=index, column=0, sticky="w", padx=(0, 8), pady=4)
            variable = tk.StringVar(value=(original or {}).get(key, "CVE-UNVERIFIED" if key == "cve" else ""))
            ttk.Entry(form, textvariable=variable).grid(row=index, column=1, sticky="ew", pady=4)
            self.inputs[key] = variable
        ttk.Label(form, text="Research stage").grid(row=7, column=0, sticky="w", pady=4)
        self.status_var = tk.StringVar(value=STATUSES[(original or {}).get("status", "new")])
        ttk.Combobox(form, textvariable=self.status_var, values=list(STATUSES.values()), state="readonly").grid(row=7, column=1, sticky="ew", pady=4)
        for index, (key, label) in enumerate((("preconditions", "Prerequisites"), ("notes", "Notes / decision rationale")), 8):
            ttk.Label(form, text=label).grid(row=index, column=0, sticky="nw", pady=6, padx=(0, 8))
            widget = scrolledtext.ScrolledText(form, height=6, wrap="word", font=("Segoe UI", 10))
            widget.grid(row=index, column=1, sticky="nsew", pady=6)
            widget.insert("1.0", (original or {}).get(key, ""))
            self.inputs[key] = widget
            form.rowconfigure(index, weight=1)
        buttons = ttk.Frame(form)
        buttons.grid(row=10, column=0, columnspan=2, sticky="e", pady=(10, 0))
        self.save_button = ttk.Button(buttons, text="Save", command=self._submit)
        self.save_button.pack(side="left", padx=6)
        ttk.Button(buttons, text="Close", command=self.destroy).pack(side="left")
        form.columnconfigure(1, weight=1)
        self.grab_set()

    def _submit(self):
        fields = {key: value.get("1.0", "end-1c") if isinstance(value, tk.Text) else value.get()
                  for key, value in self.inputs.items()}
        fields["status"] = next(key for key, label in STATUSES.items() if label == self.status_var.get())
        try:
            record = make_candidate(fields, self.original)
        except ValueError as exc:
            messagebox.showerror("ZAS — candidate", str(exc), parent=self)
            return
        self.save_button.configure(state="disabled")
        self.on_submit(record, self)


class CandidateCatalogPanel(tk.Frame):
    PAGE_SIZE = 100

    def __init__(self, parent, catalog_path, modules=None):
        super().__init__(parent, bg=COLORS["bg"])
        self.catalog_path = Path(catalog_path)
        self._modules = modules or {}
        self._advisory_client = AdvisoryClient()
        self.snapshot = None
        self._busy = False
        self._closed = False
        self._events = queue.Queue()
        self._filtered = []
        self._page = 0
        self._selected = None
        self._editor = None
        self._build_ui()
        self.bind("<Destroy>", self._on_destroy, add="+")
        self._poll_id = self.after(100, self._poll)

    def _build_ui(self):
        tk.Label(self, text="CVE candidates", font=("Consolas", 12, "bold"),
                 bg=COLORS["bg"], fg=COLORS["accent"]).pack(anchor="w", pady=(0, 8))
        ttk.Label(self, text=CATALOG_NOTE, wraplength=680, justify="left").pack(fill="x", pady=(0, 10))
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x")
        self.add_button = ttk.Button(toolbar, text="Add", command=self._add, state="disabled")
        self.edit_button = ttk.Button(toolbar, text="Edit", command=self._edit, state="disabled")
        self.import_button = ttk.Button(toolbar, text="Import JSON", command=self._import, state="disabled")
        self.export_button = ttk.Button(toolbar, text="Export JSON", command=self._export, state="disabled")
        self.refresh_button = ttk.Button(toolbar, text="Refresh", command=self.refresh)
        self.fetch_button = ttk.Button(toolbar, text="Fetch advisories", command=self._fetch_advisories, state="disabled")
        self._controls = [self.add_button, self.edit_button, self.import_button, self.export_button, self.refresh_button, self.fetch_button]
        for button in self._controls:
            button.pack(side="left", padx=(0, 6))
        self.summary = tk.StringVar(value="Open the catalog to load research entries.")
        ttk.Label(self, textvariable=self.summary, wraplength=680).pack(fill="x", pady=8)
        filters = ttk.Frame(self)
        filters.pack(fill="x")
        self.filter_var = tk.StringVar(value="All stages")
        ttk.Label(filters, text="Stage:").pack(side="left", padx=(0, 6))
        selector = ttk.Combobox(filters, textvariable=self.filter_var,
                                values=["All stages"] + list(STATUSES.values()), state="readonly", width=25)
        selector.pack(side="left")
        selector.bind("<<ComboboxSelected>>", lambda event: self._filter())
        self.search_var = tk.StringVar()
        ttk.Entry(filters, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=(8, 0))
        self.search_var.trace_add("write", lambda *_: self._filter())
        ttk.Label(self, text="Search by CVE, product or affected versions.").pack(anchor="w", pady=(3, 0))
        table = ttk.Frame(self)
        table.pack(fill="both", expand=True, pady=6)
        columns = ("cve", "product", "versions", "status", "updated")
        self.tree = ttk.Treeview(table, columns=columns, show="headings", height=10, selectmode="browse")
        for key, title, width in zip(columns, ("Claimed CVE", "Product", "Versions", "Research stage", "Updated (UTC)"), (160, 200, 150, 160, 180)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, minwidth=70)
        vertical = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self._select)
        pager = ttk.Frame(self)
        pager.pack(fill="x")
        self.previous_button = ttk.Button(pager, text="← Previous", command=lambda: self._turn_page(-1))
        self.previous_button.pack(side="left")
        self.page_var = tk.StringVar()
        ttk.Label(pager, textvariable=self.page_var).pack(side="left", padx=10)
        self.next_button = ttk.Button(pager, text="Next →", command=lambda: self._turn_page(1))
        self.next_button.pack(side="left")
        self.details = scrolledtext.ScrolledText(self, height=9, wrap="word", state="disabled", font=("Consolas", 9))
        self.details.pack(fill="both", expand=True, pady=8)
        links = ttk.Frame(self)
        links.pack(fill="x")
        self._links = []
        for text, kind in (("Open source", "poc_url"), ("Advisory", "advisory_url"), ("NVD", "nvd"), ("GHSA", "ghsa")):
            button = ttk.Button(links, text=text, command=lambda key=kind: self._open_source(key), state="disabled")
            button.pack(side="left", padx=(0, 6))
            self._links.append((button, kind))
        self._render()

    def _run(self, work, message, editor=None):
        if self._busy or self._closed:
            return False
        self._busy = True
        self.summary.set(message)
        for button in self._controls:
            button.configure(state="disabled")

        def run():
            try:
                result = work()
                self._events.put((result, None, editor))
            except (OSError, ValueError, RecursionError) as exc:
                self._events.put((None, str(exc), editor))

        threading.Thread(target=run, daemon=True, name="zas-candidate-catalog").start()
        return True

    def refresh(self):
        if self._editor is not None and self._editor.winfo_exists():
            return
        self._run(lambda: {"snapshot": load_catalog(self.catalog_path)}, "Loading catalog...")

    def _poll(self):
        if self._closed:
            return
        try:
            result, error, editor = self._events.get_nowait()
        except queue.Empty:
            pass
        else:
            self._busy = False
            if error:
                self.summary.set("Operation failed. The original catalog was preserved.")
                parent = editor if editor is not None and editor.winfo_exists() else self
                messagebox.showerror("ZAS — candidate catalog", error, parent=parent)
                if editor is not None and editor.winfo_exists():
                    if hasattr(editor, "save_failed"):
                        editor.save_failed()
                    else:
                        editor.save_button.configure(state="normal")
            else:
                if "snapshot" in result:
                    self.snapshot = result["snapshot"]
                self.summary.set(result.get("message", f"Candidates: {len(self.snapshot['candidates'])}"))
                if editor is not None and editor.winfo_exists():
                    editor.destroy()
                self._filter()
            self._update_controls()
        self._poll_id = self.after(100, self._poll)

    def _update_controls(self):
        loaded = self.snapshot is not None and not self._busy
        for button in (self.add_button, self.import_button, self.export_button, self.fetch_button):
            button.configure(state="normal" if loaded else "disabled")
        self.refresh_button.configure(state="disabled" if self._busy else "normal")
        self.edit_button.configure(state="normal" if loaded and self._selected else "disabled")

    def _filter(self):
        query = self.search_var.get().strip().casefold()
        selected_status = self.filter_var.get()
        records = self.snapshot["candidates"] if self.snapshot is not None else []
        self._filtered = sorted([record for record in records
                                 if (selected_status == "All stages" or STATUSES[record["status"]] == selected_status)
                                 and (not query or query in " ".join(record[key] for key in ("cve", "product", "versions")).casefold())],
                                key=lambda record: (record["updated_at"], record["id"]), reverse=True)
        self._page = 0
        self._render()

    def _render(self):
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        start = self._page * self.PAGE_SIZE
        for record in self._filtered[start:start + self.PAGE_SIZE]:
            self.tree.insert("", "end", iid=record["id"], values=(record["cve"], record["product"], record["versions"], STATUSES[record["status"]], record["updated_at"]))
        pages = max(1, (len(self._filtered) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self.page_var.set(f"Entries: {len(self._filtered)} · {self._page + 1}/{pages}")
        self.previous_button.configure(state="normal" if self._page else "disabled")
        self.next_button.configure(state="normal" if self._page + 1 < pages else "disabled")
        self._selected = None
        self._show_details("")
        self._update_controls()
        for button, _ in self._links:
            button.configure(state="disabled")

    def _turn_page(self, direction):
        pages = max(1, (len(self._filtered) + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self._page = max(0, min(pages - 1, self._page + direction))
        self._render()

    def _select(self, event=None):
        selection = self.tree.selection()
        if not selection or self.snapshot is None:
            return
        self._selected = next((record for record in self.snapshot["candidates"] if record["id"] == selection[0]), None)
        if self._selected is None:
            return
        record = self._selected
        text = (f"{record['cve']} — {record['product']}\n"
                f"CVE verification: UNVERIFIED\nStage: {STATUSES[record['status']]}\n"
                f"Versions: {record['versions'] or 'Not determined'}\nPoC: {record['poc_url']}\n"
                f"Advisory: {record['advisory_url'] or 'Not specified'}\nRevision: {record['revision'] or 'Not pinned'}\n\n"
                f"Prerequisites:\n{record['preconditions'] or 'Not determined'}\n\nNotes:\n{record['notes']}")
        self._show_details(text)
        for button, kind in self._links:
            enabled = bool(record.get(kind)) if kind in ("poc_url", "advisory_url") else record["cve"] != "CVE-UNVERIFIED"
            button.configure(state="normal" if enabled else "disabled")
        self._update_controls()

    def _show_details(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _add(self):
        self._edit_record(None)

    def _edit(self):
        if self._selected is not None:
            self._edit_record(self._selected)

    def _edit_record(self, original):
        if self.snapshot is None or self._busy:
            return
        if self._editor is not None and self._editor.winfo_exists():
            self._editor.lift()
            return
        self._editor = CandidateEditor(self, original, self._save_record)

    def _save_record(self, record, editor):
        records = [item for item in self.snapshot["candidates"] if item["id"] != record["id"]] + [record]
        revision = self.snapshot["revision"]
        started = self._run(lambda: {"snapshot": save_catalog(self.catalog_path, records, revision),
                                    "message": f"Entry saved. Candidates: {len(records)}"}, "Saving...", editor)
        if not started and editor.winfo_exists():
            editor.save_button.configure(state="normal")

    def _import(self):
        if self.snapshot is None or self._busy:
            return
        path = filedialog.askopenfilename(parent=self, title="Import ZAS catalog", filetypes=[("ZAS candidates JSON", "*.json")])
        if not path:
            return
        snapshot = self.snapshot

        def work():
            incoming = load_catalog(path)
            if incoming["revision"] is None:
                raise ValueError("Import file not found")
            merged = merge_candidates(snapshot["candidates"], incoming["candidates"])
            if merged["added"]:
                updated = save_catalog(self.catalog_path, merged["candidates"], snapshot["revision"])
            else:
                updated = snapshot
            return {"snapshot": updated, "message": f"Added: {merged['added']} · Duplicates skipped: {merged['skipped']}"}

        self._run(work, "Importing catalog...")

    def _fetch_advisories(self):
        if self.snapshot is None or self._busy:
            return
        if self._editor is not None and self._editor.winfo_exists():
            self._editor.lift()
            return
        self._editor = AdvisoryImportDialog(self, self._advisory_client, self.snapshot["candidates"],
                                            self._modules, self._save_advisory_cards)

    def _save_advisory_cards(self, records, dialog):
        snapshot = self.snapshot

        def work():
            merged = merge_candidates(snapshot["candidates"], records)
            updated = (save_catalog(self.catalog_path, merged["candidates"], snapshot["revision"])
                       if merged["added"] else snapshot)
            return {"snapshot": updated,
                    "message": f"Advisory cards added: {merged['added']} · Duplicates skipped: {merged['skipped']}"}

        if not self._run(work, "Saving selected advisory cards...", dialog):
            dialog.save_failed()

    def _export(self):
        if self.snapshot is None or self._busy:
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export ZAS catalog",
                                            initialfile="zas_candidates.json", defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        if Path(path).resolve() == self.catalog_path.resolve():
            messagebox.showerror("ZAS", "Choose a different path for the exported copy.", parent=self)
            return
        records = self.snapshot["candidates"]

        def work():
            destination = load_catalog(path)
            save_catalog(path, records, destination["revision"])
            return {"message": f"Catalog exported: {path}"}

        self._run(work, "Exporting catalog...")

    def _open_source(self, kind):
        if self._selected is None:
            return
        record = self._selected
        if kind == "nvd":
            url = f"https://nvd.nist.gov/vuln/detail/{record['cve']}"
        elif kind == "ghsa":
            url = f"https://github.com/advisories?query={record['cve']}"
        else:
            url = record.get(kind, "")
        try:
            validate_source_url(url, required=True)
            webbrowser.open(url, new=2)
        except (OSError, ValueError, webbrowser.Error) as exc:
            messagebox.showerror("ZAS", f"Could not open source: {exc}", parent=self)

    def _on_destroy(self, event):
        if event.widget is self:
            self._closed = True
            self.after_cancel(self._poll_id)
