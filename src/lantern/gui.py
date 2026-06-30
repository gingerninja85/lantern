from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any
import webbrowser

from lantern.inventory import Inventory, Observation
from lantern.report import render_html_report
from lantern.risk import score_observation
from lantern.scanner import observations_to_csv, parse_ports, parse_targets, scan_lan


@dataclass(frozen=True)
class GuiScanResult:
    observations: list[Observation]
    report_path: Path
    summary_text: str


class LanternApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Lantern LAN Scanner")
        self.geometry("1180x760")
        self.minsize(980, 620)
        self.configure(bg="#070912")
        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._last_report: Path | None = None
        self._build_vars()
        self._build_style()
        self._build_ui()
        self.after(100, self._poll_queue)

    def _build_vars(self) -> None:
        self.db_path = tk.StringVar(value="lantern.sqlite")
        self.report_path = tk.StringVar(value="lantern-report.html")
        self.targets = tk.StringVar(value="")
        self.cidr = tk.StringVar(value="")
        self.ports = tk.StringVar(value="quick")
        self.timeout = tk.StringVar(value="0.45")
        self.workers = tk.StringVar(value="128")
        self.baseline = tk.StringVar(value="")
        self.save_baseline = tk.StringVar(value="")
        self.use_neighbors = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Ready")

    def _build_style(self) -> None:
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.style.configure("TFrame", background="#070912")
        self.style.configure("Panel.TFrame", background="#0f172a", borderwidth=1, relief="solid")
        self.style.configure("TLabel", background="#070912", foreground="#e5f7ff")
        self.style.configure("Muted.TLabel", background="#070912", foreground="#8aa4b5")
        self.style.configure("Panel.TLabel", background="#0f172a", foreground="#e5f7ff")
        self.style.configure("Header.TLabel", background="#070912", foreground="#22d3ee", font=("Segoe UI", 22, "bold"))
        self.style.configure("Accent.TButton", background="#22d3ee", foreground="#001014", font=("Segoe UI", 10, "bold"))
        self.style.configure("TButton", padding=7)
        self.style.configure("TCheckbutton", background="#070912", foreground="#e5f7ff")
        self.style.configure("Treeview", background="#0b1220", foreground="#e5f7ff", fieldbackground="#0b1220", rowheight=28)
        self.style.configure("Treeview.Heading", background="#111827", foreground="#22d3ee", font=("Segoe UI", 10, "bold"))

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=18)
        root.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(root)
        header.pack(fill=tk.X)
        ttk.Label(header, text="🔦 Lantern", style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(
            header,
            text="LAN scanner, inventory, baseline diff, and risk dashboard",
            style="Muted.TLabel",
        ).pack(side=tk.LEFT, padx=14)

        panes = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, pady=(16, 10))

        left = ttk.Frame(panes, style="Panel.TFrame", padding=14)
        right = ttk.Frame(panes, padding=(14, 0, 0, 0))
        panes.add(left, weight=0)
        panes.add(right, weight=1)

        self._build_controls(left)
        self._build_results(right)

        bottom = ttk.Frame(root)
        bottom.pack(fill=tk.X)
        ttk.Label(bottom, textvariable=self.status, style="Muted.TLabel").pack(side=tk.LEFT)
        ttk.Button(bottom, text="Open Last Report", command=self._open_last_report).pack(side=tk.RIGHT)

    def _build_controls(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Scan settings", style="Panel.TLabel", font=("Segoe UI", 13, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        self._entry_row(parent, 1, "Database", self.db_path, browse=lambda: self._browse_save(self.db_path, "SQLite DB", "*.sqlite"))
        self._entry_row(parent, 2, "Report", self.report_path, browse=lambda: self._browse_save(self.report_path, "HTML report", "*.html"))
        self._entry_row(parent, 3, "Targets", self.targets, hint="10.0.0.1,10.0.0.147")
        self._entry_row(parent, 4, "CIDR", self.cidr, hint="10.0.0.0/24")
        self._entry_row(parent, 5, "Ports", self.ports, hint="quick, extended, all, 22,80,8000-8100")
        self._entry_row(parent, 6, "Timeout", self.timeout)
        self._entry_row(parent, 7, "Workers", self.workers)
        self._entry_row(parent, 8, "Compare baseline", self.baseline)
        self._entry_row(parent, 9, "Save baseline", self.save_baseline)

        ttk.Checkbutton(parent, text="Use Windows neighbor cache / local ARP", variable=self.use_neighbors).grid(row=10, column=0, columnspan=3, sticky="w", pady=10)
        ttk.Button(parent, text="Run Scan", style="Accent.TButton", command=self._run_scan_clicked).grid(row=11, column=0, columnspan=3, sticky="ew", pady=(4, 8))
        ttk.Button(parent, text="Refresh Inventory", command=self._refresh_inventory).grid(row=12, column=0, columnspan=3, sticky="ew", pady=4)
        ttk.Button(parent, text="Export JSON", command=lambda: self._export("json")).grid(row=13, column=0, columnspan=3, sticky="ew", pady=4)
        ttk.Button(parent, text="Export CSV", command=lambda: self._export("csv")).grid(row=14, column=0, columnspan=3, sticky="ew", pady=4)

        ttk.Label(parent, text="Safety: only scan networks you own or are authorized to assess.", style="Panel.TLabel", wraplength=320).grid(row=15, column=0, columnspan=3, sticky="ew", pady=(16, 0))
        parent.columnconfigure(1, weight=1)

    def _entry_row(self, parent: ttk.Frame, row: int, label: str, var: tk.StringVar, browse=None, hint: str | None = None) -> None:  # type: ignore[no-untyped-def]
        ttk.Label(parent, text=label, style="Panel.TLabel").grid(row=row, column=0, sticky="w", pady=5)
        entry = ttk.Entry(parent, textvariable=var, width=30)
        entry.grid(row=row, column=1, sticky="ew", padx=(8, 4), pady=5)
        if browse:
            ttk.Button(parent, text="…", width=3, command=browse).grid(row=row, column=2, sticky="ew", pady=5)
        elif hint:
            ttk.Label(parent, text="?", style="Panel.TLabel").grid(row=row, column=2, sticky="w", pady=5)

    def _build_results(self, parent: ttk.Frame) -> None:
        columns = ("ip", "mac", "hostname", "vendor", "risk", "ports")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings")
        headings = {
            "ip": "IP",
            "mac": "MAC",
            "hostname": "Hostname",
            "vendor": "Vendor / Interface",
            "risk": "Risk",
            "ports": "Open ports",
        }
        widths = {"ip": 120, "mac": 150, "hostname": 150, "vendor": 160, "risk": 100, "ports": 300}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=80, stretch=col == "ports")
        self.tree.pack(fill=tk.BOTH, expand=True)

        ttk.Label(parent, text="Log", style="Muted.TLabel").pack(anchor="w", pady=(12, 4))
        self.log = tk.Text(parent, height=8, bg="#020617", fg="#d1f7ff", insertbackground="#22d3ee", relief=tk.FLAT)
        self.log.pack(fill=tk.X)

    def _browse_save(self, var: tk.StringVar, title: str, pattern: str) -> None:
        chosen = filedialog.asksaveasfilename(title=title, filetypes=[(title, pattern), ("All files", "*.*")])
        if chosen:
            var.set(chosen)

    def _inventory(self) -> Inventory:
        return Inventory(Path(self.db_path.get()).expanduser())

    def _run_scan_clicked(self) -> None:
        try:
            target_list = parse_targets(self.targets.get() or None, self.cidr.get() or None)
            port_list = parse_ports(self.ports.get())
            timeout = float(self.timeout.get())
            workers = int(self.workers.get())
        except Exception as exc:
            messagebox.showerror("Invalid scan settings", str(exc))
            return

        self.status.set("Scanning…")
        self._set_controls_state(tk.DISABLED)
        self._log("Starting scan…")
        thread = threading.Thread(
            target=self._scan_worker,
            args=(target_list, port_list, timeout, workers),
            daemon=True,
        )
        thread.start()

    def _scan_worker(self, target_list: list[str], port_list: list[int], timeout: float, workers: int) -> None:
        try:
            inventory = self._inventory()
            observations, summary = scan_lan(
                targets=target_list,
                ports=port_list,
                timeout=timeout,
                workers=workers,
                include_neighbors=self.use_neighbors.get(),
            )
            for observation in observations:
                inventory.record_observation(observation)
            if self.save_baseline.get().strip():
                inventory.mark_baseline(self.save_baseline.get().strip())
            report_path = Path(self.report_path.get()).expanduser()
            rendered = render_html_report(inventory, baseline=self.baseline.get().strip() or None)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(rendered, encoding="utf-8")
            text = f"Scanned {summary.targets} targets; found {summary.open_ports} open TCP ports."
            self._queue.put(("scan_done", GuiScanResult(inventory.list_devices(), report_path, text)))
        except Exception as exc:
            self._queue.put(("error", exc))

    def _poll_queue(self) -> None:
        try:
            while True:
                event, payload = self._queue.get_nowait()
                if event == "scan_done":
                    result = payload
                    assert isinstance(result, GuiScanResult)
                    self._last_report = result.report_path
                    self._populate_tree(result.observations)
                    self._log(result.summary_text)
                    self._log(f"Report written: {result.report_path}")
                    self.status.set("Ready")
                    self._set_controls_state(tk.NORMAL)
                    if messagebox.askyesno("Scan complete", f"{result.summary_text}\n\nOpen the HTML report now?"):
                        webbrowser.open(result.report_path.resolve().as_uri())
                elif event == "error":
                    self.status.set("Error")
                    self._set_controls_state(tk.NORMAL)
                    self._log(f"ERROR: {payload}")
                    messagebox.showerror("Lantern error", str(payload))
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _set_controls_state(self, state: str) -> None:
        for child in self.winfo_children():
            self._set_state_recursive(child, state)

    def _set_state_recursive(self, widget: Any, state: str) -> None:
        for child in widget.winfo_children():
            if isinstance(child, (ttk.Button, ttk.Entry, ttk.Checkbutton)):
                try:
                    child.configure(state=state)
                except tk.TclError:
                    pass
            self._set_state_recursive(child, state)

    def _refresh_inventory(self) -> None:
        try:
            self._populate_tree(self._inventory().list_devices())
            self._log("Inventory refreshed.")
        except Exception as exc:
            messagebox.showerror("Refresh failed", str(exc))

    def _populate_tree(self, observations: list[Observation]) -> None:
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        for obs in sorted(observations, key=lambda item: tuple(int(part) for part in item.ip.split("."))):
            risk = score_observation(obs)
            self.tree.insert(
                "",
                tk.END,
                values=(
                    obs.ip,
                    obs.mac or "",
                    obs.hostname or "",
                    obs.vendor or "",
                    f"{risk.level} ({risk.score})",
                    ", ".join(port.label for port in obs.ports),
                ),
            )

    def _export(self, export_format: str) -> None:
        try:
            devices = self._inventory().list_devices()
            if export_format == "csv":
                rendered = observations_to_csv(devices)
                default = "lantern-devices.csv"
            else:
                import json

                rendered = json.dumps([
                    {
                        "ip": d.ip,
                        "mac": d.mac,
                        "hostname": d.hostname,
                        "vendor": d.vendor,
                        "ports": [p.__dict__ for p in d.ports],
                    }
                    for d in devices
                ], indent=2) + "\n"
                default = "lantern-devices.json"
            chosen = filedialog.asksaveasfilename(initialfile=default)
            if chosen:
                Path(chosen).write_text(rendered, encoding="utf-8")
                self._log(f"Exported {export_format}: {chosen}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _open_last_report(self) -> None:
        report = self._last_report or Path(self.report_path.get()).expanduser()
        if report.exists():
            webbrowser.open(report.resolve().as_uri())
        else:
            messagebox.showinfo("No report", "No report file exists yet.")

    def _log(self, text: str) -> None:
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)


def main() -> None:
    app = LanternApp()
    app.mainloop()


if __name__ == "__main__":
    main()
