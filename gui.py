from __future__ import annotations
import threading, queue, csv, os, tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scanner import run_comprehensive_scan
from scanner import save_findings_to_file
import ipaddress

GWL_EXSTYLE = -20
WS_EX_APPWINDOW = 0x00040000
WS_EX_TOOLWINDOW = 0x00000080


SEV_COLOUR = {
    "Critical": "#f8d7da",
    "High": "#ffe5b4",
    "Medium": "#fff3cd",
    "Low": "#d4edda",
    "Info": "#e2e3e5",
}

DEFAULT_FONT = ("Aptos", 10)


class SentinelGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Fairweather Sentinel")
        self.geometry("1200x700")
        self._offset_x = 0
        self._offset_y = 0

        self.title_bar = tk.Frame(self, bg="#6b73d6", relief="raised", bd=0, height=30)
        self.title_bar.pack(fill="x")

        tk.Label(self.title_bar, text="Fairweather Sentinel", fg="white", bg="#6b73d6",
                 font=("Aptos", 10, "bold")).pack(side="left", padx=10)
        tk.Button(self.title_bar, text="✕", command=self.destroy, bg="#6b73d6", fg="white", bd=0).pack(side="right",
                                                                                                       padx=5)

        self.title_bar.bind("<Button-1>", self.start_move)
        self.title_bar.bind("<B1-Motion>", self.do_move)

        self.grip = tk.Label(self, bg="#6b73d6", cursor="bottom_right_corner")
        self.grip.place(relx=1.0, rely=1.0, anchor="se")
        self.grip.bind("<B1-Motion>", self.resize_window)

        self._apply_theme()
        self._build_widgets()

        icon_path = os.path.join("assets", "logo.png")
        if os.path.exists(icon_path):
            self.iconbitmap("assets/logo.ico")

        self._q: queue.Queue = queue.Queue()
        self._scan_thread: threading.Thread | None = None
        self.after(200, self._poll_queue)
        self.configure(bg="#d6e2fb")

        self.scan_results = None

    def _save_report_as_csv(self):
        if not hasattr(self, 'findings') or not self.findings:
            messagebox.showwarning("No Data", "No findings available to save.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save Traffic Report As"
        )
        if filename:
            save_findings_to_file(self.findings, filename, file_format="csv")
            messagebox.showinfo("Success", f"Findings saved to:\n{filename}")

    def start_move(self, event):
        self._offset_x = event.x
        self._offset_y = event.y

    def do_move(self, event):
        x = self.winfo_pointerx() - self._offset_x
        y = self.winfo_pointery() - self._offset_y
        self.geometry(f"+{x}+{y}")

    def resize_window(self, event):
        width = self.winfo_pointerx() - self.winfo_rootx()
        height = self.winfo_pointery() - self.winfo_rooty()
        self.geometry(f"{width}x{height}")

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("default")

        style.configure("Treeview",
                        background="#d6e2fb",
                        foreground="black",
                        fieldbackground="#d6e2fb",
                        font=("Aptos", 10),
                        rowheight=24)

        style.configure("Treeview.Heading",
                        background="#6b73d6",
                        foreground="white",
                        font=("Aptos", 10, "bold"))

        style.map("Treeview",
                  background=[("selected", "#cce5ff")],
                  foreground=[("selected", "black")])

        style.configure("TLabel", font=("Aptos", 10), foreground="black")
        style.configure("TButton", font=("Aptos", 10), foreground="black")
        style.configure("TEntry", font=("Aptos", 10), foreground="black")
        style.configure("TCombobox", font=("Aptos", 10), foreground="black")

        style.configure("Moody.Vertical.TScrollbar",
                        background="#4a6fa5",
                        troughcolor="#d6e2fb",
                        bordercolor="#3a4f6f",
                        arrowcolor="white",
                        relief="flat")

    def _build_widgets(self) -> None:
        top = tk.Frame(self, bg="#ac8aec", padx=8, pady=8)
        top.pack(fill="x")

        row1 = tk.Frame(top, bg="#ac8aec")
        row1.pack(fill="x", pady=(0, 5))

        tk.Label(row1, text="Target:", bg="#6b73d6", fg="white",
                 font=("Aptos", 10, "bold")).pack(side="left")

        self.entry_target = tk.Entry(row1, width=25, font=("Aptos", 10))
        self.entry_target.pack(side="left", padx=5)

        tk.Label(row1, text="Scan Mode:", bg="#6b73d6", fg="white",
                 font=("Aptos", 10, "bold")).pack(side="left", padx=(10, 0))

        self.scan_mode_var = tk.StringVar(value="fast")
        mode_combo = ttk.Combobox(row1, textvariable=self.scan_mode_var,
                                  values=["fast", "balanced", "thorough"],
                                  width=10, state="readonly")
        mode_combo.pack(side="left", padx=5)

        tk.Label(row1, text="Traffic Duration:", bg="#6b73d6", fg="white",
                 font=("Aptos", 10, "bold")).pack(side="left", padx=(10, 0))

        self.traffic_duration_var = tk.StringVar(value="60")
        duration_entry = tk.Entry(row1, textvariable=self.traffic_duration_var, width=8)
        duration_entry.pack(side="left", padx=5)

        tk.Label(row1, text="sec", bg="#ac8aec", fg="black",
                 font=("Aptos", 10)).pack(side="left")

        row2 = tk.Frame(top, bg="#ac8aec")
        row2.pack(fill="x")

        tk.Button(row2, text="Comprehensive Scan", command=self.start_comprehensive_scan,
                  font=("Aptos", 10, "bold"), bg="#6b73d6", fg="white",
                  activebackground="#005fa3", activeforeground="white",
                  relief="raised", bd=2, padx=15).pack(side="left", padx=5)

        tk.Button(row2, text="Export CSV", command=self.export_csv,
                  font=("Aptos", 10, "bold"), bg="#28a745", fg="white",
                  padx=10).pack(side="left", padx=5)

        tk.Button(row2, text="Generate Report", command=self.generate_comprehensive_report,
                  font=("Aptos", 10, "bold"), bg="#17a2b8", fg="white",
                  padx=10).pack(side="left", padx=5)

        tk.Button(row2, text="Prioritize Vulnerabilities", command=self.prioritize_vulnerabilities,
                  font=("Aptos", 10, "bold"), bg="#ffc107", fg="black", padx=10).pack(side="left", padx=5)

        tk.Button(
            row2,
            text="Save Traffic Report as CSV",
            command=self._save_report_as_csv,
            font=("Aptos", 10, "bold"),
            bg="#17a2b8",
            fg="white",
            padx=10
        ).pack(side="left", padx=5)

        status_frame = tk.Frame(row2, bg="#ac8aec")
        status_frame.pack(side="right", padx=10)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.status_var, bg="#908cdd",
                 font=("Aptos", 10, "bold")).pack()

        self.stats_var = tk.StringVar(value="")
        tk.Label(status_frame, textvariable=self.stats_var, bg="#ac8aec",
                 font=("Aptos", 9)).pack()

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self.port_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.port_frame, text="🔍 Port Scan Results")

        port_cols = ("host", "port", "service", "product", "severity", "cvss", "cve_ids", "misconfig")
        self.port_tree = ttk.Treeview(self.port_frame, columns=port_cols, show="headings")

        col_widths = {"host": 120, "port": 60, "service": 100, "product": 150,
                      "severity": 80, "cvss": 60, "cve_ids": 200, "misconfig": 250}

        for col in port_cols:
            self.port_tree.heading(col, text=col.replace("_", " ").title())
            self.port_tree.column(col, width=col_widths.get(col, 100), anchor="center")

        port_vsb = ttk.Scrollbar(self.port_frame, orient="vertical",
                                 command=self.port_tree.yview, style="Moody.Vertical.TScrollbar")
        self.port_tree.configure(yscrollcommand=port_vsb.set)

        self.port_tree.pack(side="left", fill="both", expand=True)
        port_vsb.pack(side="right", fill="y")

        self.traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.traffic_frame, text="🌐 Network Traffic")

        traffic_cols = ("type", "category", "host", "port", "service", "severity", "description")
        self.traffic_tree = ttk.Treeview(self.traffic_frame, columns=traffic_cols, show="headings")

        traffic_widths = {"type": 120, "category": 150, "host": 120, "port": 60,
                          "service": 100, "severity": 80, "description": 300}

        for col in traffic_cols:
            self.traffic_tree.heading(col, text=col.replace("_", " ").title())
            self.traffic_tree.column(col, width=traffic_widths.get(col, 100), anchor="center")

        traffic_vsb = ttk.Scrollbar(self.traffic_frame, orient="vertical",
                                    command=self.traffic_tree.yview, style="Moody.Vertical.TScrollbar")
        self.traffic_tree.configure(yscrollcommand=traffic_vsb.set)

        self.traffic_tree.pack(side="left", fill="both", expand=True)
        traffic_vsb.pack(side="right", fill="y")

        self.summary_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.summary_frame, text="📈 Summary")

        self._build_summary_tab()

        for tree in [self.port_tree, self.traffic_tree]:
            for sev, col in SEV_COLOUR.items():
                tree.tag_configure(sev, background=col, foreground="black")

    def prioritize_vulnerabilities(self):
        """Sort and highlight the most critical vulnerabilities"""
        if not self.scan_results:
            messagebox.showinfo("No Data", "Run a scan first.")
            return

        critical_list = sorted(
            [f for f in self.scan_results.get("findings", []) if f.get("severity") in ("Critical", "High")],
            key=lambda x: x.get("cvss") or 0, reverse=True
        )

        if not critical_list:
            messagebox.showinfo("No Critical Vulnerabilities", "No high or critical vulnerabilities found.")
            return

        report_lines = []
        for i, finding in enumerate(critical_list, 1):
            line = f"{i}. {finding.get('host', 'N/A')}:{finding.get('port', 'N/A')} | " \
                   f"{finding.get('service', 'N/A')} - Severity: {finding.get('severity')}"

            cves = finding.get('cves', [])
            if cves:
                cve_info = ', '.join(f"{c.get('id')} (CVSS: {c.get('cvss', 'N/A')})" for c in cves)
                line += f"\n   CVEs: {cve_info}"

            misconf = finding.get("misconfig", [])
            if misconf:
                line += f"\n   Issues: {len(misconf)} misconfigurations"

            desc = finding.get("description")
            if desc:
                line += f"\n   Description: {desc}"

            report_lines.append(line + "\n")

        report_text = "\n".join(report_lines)
        self._show_report_window(report_text, "Prioritized Vulnerabilities")

    def _build_summary_tab(self):
        main_frame = tk.Frame(self.summary_frame, bg="#f8f9fa", padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)

        title_label = tk.Label(main_frame, text="Vulnerability Assessment Summary",
                               font=("Aptos", 14, "bold"), bg="#f8f9fa", fg="#2c3e50")
        title_label.pack(pady=(0, 20))

        stats_frame = tk.Frame(main_frame, bg="#f8f9fa")
        stats_frame.pack(fill="x", pady=(0, 20))

        self.summary_labels = {}
        stat_names = ["Total Findings", "Critical", "High", "Medium", "Low", "CVEs Found", "Traffic Issues"]
        colors = ["#34495e", "#e74c3c", "#e67e22", "#f39c12", "#27ae60", "#9b59b6", "#3498db"]

        for i, (name, color) in enumerate(zip(stat_names, colors)):
            card = tk.Frame(stats_frame, bg=color, relief="raised", bd=2)
            card.grid(row=i // 4, column=i % 4, padx=10, pady=10, sticky="ew")

            tk.Label(card, text="0", font=("Aptos", 18, "bold"),
                     bg=color, fg="white").pack(pady=(10, 5))
            tk.Label(card, text=name, font=("Aptos", 10),
                     bg=color, fg="white").pack(pady=(0, 10))

            self.summary_labels[name.lower().replace(" ", "_")] = card.winfo_children()[0]

        for i in range(4):
            stats_frame.columnconfigure(i, weight=1)

        details_frame = tk.LabelFrame(main_frame, text="Recent Scan Details",
                                      font=("Aptos", 12, "bold"), bg="#f8f9fa", fg="#2c3e50")
        details_frame.pack(fill="both", expand=True, pady=(10, 0))

        self.details_text = tk.Text(details_frame, font=("Consolas", 10),
                                    bg="white", fg="black", wrap="word", height=15)
        self.details_text.pack(fill="both", expand=True, padx=10, pady=10)

    def start_comprehensive_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showwarning("Scan running", "Please wait for current scan to complete.")
            return

        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Input error", "Enter a target host or IP.")
            return

        try:
            ipaddress.ip_address(target)
        except ValueError:
            messagebox.showerror("Input error", "Invalid IP address format.")
            return

        try:
            duration = int(self.traffic_duration_var.get())
        except ValueError:
            messagebox.showerror("Input error", "Traffic duration must be a number.")
            return

        scan_mode = self.scan_mode_var.get()

        self.status_var.set(f"Running comprehensive scan on {target}...")
        self.stats_var.set(f"Mode: {scan_mode} | Traffic: {duration}s")

        self.port_tree.delete(*self.port_tree.get_children())
        self.traffic_tree.delete(*self.traffic_tree.get_children())

        self._scan_thread = threading.Thread(
            target=lambda: self._do_comprehensive_scan(target, duration, scan_mode),
            daemon=True
        )
        self._scan_thread.start()

    def _do_comprehensive_scan(self, target: str, duration: int, scan_mode: str) -> None:
        try:
            results = run_comprehensive_scan(target, duration, scan_mode)
            self.findings = results['findings']
            self._q.put(("DONE", results))
        except Exception as exc:
            self._q.put(("ERR", str(exc)))

    def _poll_queue(self) -> None:
        try:
            msg, payload = self._q.get_nowait()
        except queue.Empty:
            self.after(200, self._poll_queue)
            return

        if msg == "DONE":
            self._populate_results(payload)
            self._update_summary(payload)
            total_findings = payload.get('total_findings', 0)
            self.status_var.set(f"Scan complete - {total_findings} findings")
            self.stats_var.set(
                f"Nmap: {payload.get('nmap_findings', 0)} | Traffic: {payload.get('traffic_findings', 0)}")
        elif msg == "ERR":
            messagebox.showerror("Scan error", payload)
            self.status_var.set("Error occurred")
            self.stats_var.set("")

        self.after(200, self._poll_queue)

    def _populate_results(self, results: dict) -> None:
        self.scan_results = results
        findings = results.get('findings', [])

        for tree in [self.port_tree, self.traffic_tree]:
            tree.delete(*tree.get_children())

        if not findings:
            self.port_tree.insert("", "end", values=("No findings",) * 8)
            self.traffic_tree.insert("", "end", values=("No traffic data",) * 7)
            return

        for finding in findings:
            finding_type = finding.get('type', 'unknown')

            if finding_type == 'nmap_scan':
                cve_ids = ", ".join(c.get("id", "") for c in finding.get("cves", []))
                misconf = "; ".join(finding.get("misconfig", []))

                self.port_tree.insert("", "end",
                                      values=(
                                          finding.get("host", "N/A"),
                                          finding.get("port", "N/A"),
                                          finding.get("service", "N/A"),
                                          finding.get("product", "N/A"),
                                          finding.get("severity", "Info"),
                                          finding.get("cvss", "N/A"),
                                          cve_ids if cve_ids else "None",
                                          misconf if misconf else "None"
                                      ),
                                      tags=(finding.get("severity", "Info"),))

            elif finding_type == 'network_traffic':
                self.traffic_tree.insert("", "end",
                                         values=(
                                             finding.get("type", "N/A"),
                                             finding.get("category", "General"),
                                             finding.get("host", "N/A"),
                                             finding.get("port", "N/A"),
                                             finding.get("service", "N/A"),
                                             finding.get("severity", "Info"),
                                             finding.get("description", "No suspicious activity")
                                         ),
                                         tags=(finding.get("severity", "Info"),))

    def _update_summary(self, results: dict) -> None:
        severity_counts = results.get('severity_breakdown', {})

        stats_updates = {
            'total_findings': results.get('total_findings', 0),
            'critical': severity_counts.get('Critical', 0),
            'high': severity_counts.get('High', 0),
            'medium': severity_counts.get('Medium', 0),
            'low': severity_counts.get('Low', 0),
            'cves_found': results.get('total_cves', 0),
            'traffic_issues': results.get('traffic_findings', 0)
        }

        for key, value in stats_updates.items():
            if key in self.summary_labels:
                self.summary_labels[key].config(text=str(value))

        self.details_text.delete(1.0, tk.END)

        details = f"""
Target: {results.get('target', 'N/A')}
Scan Time: {results.get('timestamp', 'N/A')}
Total Findings: {results.get('total_findings', 0)}

• Port Scan (Nmap): {results.get('nmap_findings', 0)} findings
• Network Traffic: {results.get('traffic_findings', 0)} findings

• Critical: {severity_counts.get('Critical', 0)}
• High: {severity_counts.get('High', 0)}
• Medium: {severity_counts.get('Medium', 0)}
• Low: {severity_counts.get('Low', 0)}
• Info: {severity_counts.get('Info', 0)}

Total CVEs Identified: {results.get('total_cves', 0)}

Traffic Analysis Duration: Configured duration
Network Issues Detected: {results.get('traffic_findings', 0)}
        """

        self.details_text.insert(1.0, details.strip())

    def export_csv(self) -> None:
        if not self.scan_results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save comprehensive results as…",
        )
        if not path:
            return

        findings = self.scan_results.get('findings', [])

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Type", "Host", "Port", "Service", "Product", "Severity",
                             "CVSS", "CVEs", "Description/Misconfig", "Category"])

            for finding in findings:
                finding_type = finding.get('type', 'unknown')

                if finding_type == 'nmap_scan':
                    cve_ids = ", ".join(c.get("id", "") for c in finding.get("cves", []))
                    misconf = "; ".join(finding.get("misconfig", []))

                    writer.writerow([
                        "Port Scan",
                        finding.get("host", ""),
                        finding.get("port", ""),
                        finding.get("service", ""),
                        finding.get("product", ""),
                        finding.get("severity", ""),
                        finding.get("cvss", ""),
                        cve_ids,
                        misconf,
                        "Nmap Detection"
                    ])
                elif finding_type == 'network_traffic':
                    writer.writerow([
                        "Network Traffic",
                        finding.get("host", "N/A"),
                        finding.get("port", "N/A"),
                        finding.get("service", "N/A"),
                        "",
                        finding.get("severity", ""),
                        finding.get("cvss", ""),
                        "",
                        finding.get("description", ""),
                        finding.get("category", "")
                    ])

        messagebox.showinfo("Exported", f"Comprehensive results exported to:\n{os.path.abspath(path)}")

    def generate_comprehensive_report(self):
        if not self.scan_results:
            messagebox.showinfo("No data", "Run a scan first.")
            return

        findings = self.scan_results.get('findings', [])

        port_map = {}
        all_ports = set()

        for finding in findings:
            if finding.get('type') != 'nmap_scan':
                continue

            port = finding.get('port')
            service = finding.get('service', 'unknown')
            cves = finding.get('cves', [])

            key = (port, service)
            all_ports.add(key)

            if key not in port_map:
                port_map[key] = []

            for cve in cves:
                cve_id = cve.get('id', 'Unknown CVE')
                # Use the full description from nmap's vuln script output
                description = cve.get('description', '')
                if description:
                    # Clean up the description - remove the CVE ID if it's at the start
                    clean_desc = description
                    if clean_desc.startswith(cve_id):
                        clean_desc = clean_desc[len(cve_id):].strip()
                        if clean_desc.startswith(':'):
                            clean_desc = clean_desc[1:].strip()

                    port_map[key].append(f"{cve_id}: {clean_desc}")
                else:
                    port_map[key].append(f"{cve_id}: No description available")

        sorted_ports = sorted(all_ports, key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0)

        report_lines = []
        for port, service in sorted_ports:
            report_lines.append(f"Port {port} ({service}):")
            cve_descriptions = port_map.get((port, service), [])
            if cve_descriptions:
                for desc in cve_descriptions:
                    report_lines.append(desc)
            report_lines.append("")

        report_text = "\n".join(report_lines)

        save_path = filedialog.asksaveasfilename(
            title="Save Comprehensive CVE Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if save_path:
            try:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(report_text)
                messagebox.showinfo("Report Saved", f"Report saved to:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report:\n{e}")

    def start_comprehensive_scan_from_scheduler(self, ip: str, mode: str):
        try:
            self.entry_target.delete(0, tk.END)
            self.entry_target.insert(0, ip)

            self.scan_mode_var.set(mode)
            self.traffic_duration_var.set("60")

            self.after(300, self.start_comprehensive_scan)
        except Exception as e:
            messagebox.showerror("Scheduled Scan Error", f"Failed to start scan:\n{e}")

    def _show_report_window(self, report_text: str, title: str = "Report") -> None:
        win = tk.Toplevel(self)
        win.title(title)
        win.geometry("900x700")
        win.configure(bg="#f5f5f5")

        font = ("Consolas", 10)

        text_frame = tk.Frame(win)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        txt = tk.Text(text_frame, wrap="word", font=font, bg="white", fg="black")
        scrollbar = tk.Scrollbar(text_frame, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=scrollbar.set)

        txt.insert("1.0", report_text)
        txt.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        btns = tk.Frame(win, bg="#f5f5f5")
        btns.pack(fill="x", pady=(0, 10))

        def save_report():
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                title="Save Report As…"
            )
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(txt.get("1.0", "end-1c"))
                messagebox.showinfo("Saved", f"Report saved to:\n{path}")

        tk.Button(btns, text="Save Report", command=save_report, font=("Aptos", 10),
                  bg="#6b73d6", fg="white", relief="raised", padx=15).pack(side="left", padx=10)

        tk.Button(btns, text="Close", command=win.destroy, font=("Aptos", 10),
                  bg="#d9534f", fg="white", relief="raised", padx=15).pack(side="right", padx=10)

if __name__ == "__main__":
    SentinelGUI().mainloop()