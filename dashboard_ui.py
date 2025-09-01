import tkinter as tk
from gui import SentinelGUI
from tkinter import filedialog, messagebox, simpledialog
import textwrap
import json
import re
import requests
import os
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import hashlib
from PIL import Image, ImageTk
import sys
import datetime
import threading
import pystray
from PIL import Image as PILImage, ImageDraw
import time
from datetime import datetime
import ipaddress

GROQ_API_KEY = ""
GROQ_API_URL = ""
NVD_API_KEY = ""
NVD_API_URL = ""


def get_db_path():
    db_folder = "CVE-sol-db"
    os.makedirs(db_folder, exist_ok=True)
    return os.path.join(db_folder, "cve-sol-db.json")

def load_cve_db():
    db_file = get_db_path()
    if os.path.exists(db_file):
        with open(db_file, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print("[DB] Corrupted JSON file. Starting new DB.")
                return {}
    return {}

def save_cve_db(db):
    with open(get_db_path(), "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)

def safe_cvss_score(entry):
    try:
        return float(entry.get("cvss", 0.0))
    except (ValueError, TypeError):
        return 0.0

def fetch_cvss_from_nvd(cve_id):
    try:
        headers = {"apiKey": NVD_API_KEY}
        response = requests.get(NVD_API_URL + cve_id, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return "Unknown"

        metrics = vulnerabilities[0]["cve"].get("metrics", {})

        if "cvssMetricV31" in metrics:
            return str(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV2" in metrics:
            return str(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])
        else:
            return "Unknown"

    except Exception as e:
        print(f"[ERROR] {cve_id} – {e}")
        return "Unknown"
    finally:
        time.sleep(1.5)

def update_cvss_in_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    updated = 0

    for entry in data:
        if not entry.get("cve_id"):
            continue

        if "cvss" not in entry or entry["cvss"] in ["", "Unknown", None]:
            cve_id = entry["cve_id"]
            score = fetch_cvss_from_nvd(cve_id)
            entry["cvss"] = score
            updated += 1
            print(f"[+] Updated {cve_id} with CVSS: {score}")

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"\n✔ Done. {updated} entries updated with CVSS scores.")

update_cvss_in_json("CVE-sol-db/cve-sol-db.json")

def schedule_scan(target_ip, scan_mode, start_time_str):
    now = datetime.now()
    target_time = datetime.strptime(start_time_str, "%H:%M").replace(
        year=now.year, month=now.month, day=now.day
    )
    if target_time < now:
        target_time += datetime.timedelta(days=1)

    wait_seconds = (target_time - now).total_seconds()

    def delayed_scan():
        print(f"[Scheduler] Waiting {wait_seconds:.0f} seconds until scan for {target_ip}")
        time.sleep(wait_seconds)

        print(f"[Scheduler] Starting scan: {scan_mode} on {target_ip}")
        gui = SentinelGUI()
        gui.after(100, lambda: gui.start_comprehensive_scan_from_scheduler(target_ip, scan_mode))
        gui.mainloop()

    def quit_tray(icon, item=None):
        icon.stop()

    threading.Thread(target=delayed_scan, daemon=True).start()
    create_tray_icon(quit_tray)

def create_tray_icon(on_quit):
    icon_image = PILImage.new("RGB", (64, 64), "blue")
    draw = ImageDraw.Draw(icon_image)
    draw.text((10, 25), "F", fill="white")

    def setup(icon):
        icon.visible = True

    icon = pystray.Icon("Fairweather", icon_image, "Fairweather Sentinel", menu=pystray.Menu(
        pystray.MenuItem("Quit", on_quit)
    ))

    threading.Thread(target=icon.run, daemon=True).start()

def fetch_solution_from_groq(cve_id):
    import requests
    import re

    print(f"[Groq AI] Fetching SOLUTION ONLY for: {cve_id}")

    db = load_cve_db()
    if cve_id in db and db[cve_id].get("solution"):
        print("[Groq AI] Solution already exists in DB.")
        return db[cve_id]["solution"]

    try:
        response = requests.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama3-70b-8192",
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity assistant. Respond ONLY with:\n"
                            "Solution: <concise solution in 2 sentences. No intro, no CVSS.>"
                        )
                    },
                    {
                        "role": "user",
                        "content": f"{cve_id}"
                    }
                ]
            },
            timeout=15
        )

        if response.status_code == 200:
            reply = response.json()['choices'][0]['message']['content'].strip()
            print(f"[Groq AI] Raw solution response:\n{reply}")

            solution_match = re.search(r"Solution:\s*(.+)", reply, re.IGNORECASE)
            solution = solution_match.group(1).strip() if solution_match else reply.strip()

            if cve_id not in db:
                db[cve_id] = {}
            db[cve_id]["solution"] = solution
            save_cve_db(db)

            print(f"[Groq AI] Stored solution:\n{solution}")
            return solution

        else:
            print(f"[Groq AI] API Error {response.status_code}: {response.text}")
            return "Could not retrieve solution."

    except Exception as e:
        print(f"[Groq AI] Exception: {e}")
        return "Error: Failed to connect to Groq AI."

class LoginDialog(simpledialog.Dialog):

    def __init__(self, parent, title=None):
        self.result = None
        super().__init__(parent, title)

    def cancel(self, event=None):
        self.result = None
        self.destroy()

    def body(self, master):
        self.set_geometry("400x400")

        self.configure(bg="#d6e2fb")
        master.configure(bg="#d6e2fb")

        logo_img = Image.open("assets/logo.png")
        logo_img = logo_img.resize((120, 120), Image.Resampling.LANCZOS)
        self.logo_photo = ImageTk.PhotoImage(logo_img)

        logo_label = tk.Label(master, image=self.logo_photo, bg="#d6e2fb")
        logo_label.grid(row=0, column=0, columnspan=2, pady=(20, 10))

        tk.Label(master, bg="#6b73d6", fg="white", font=("Aptos", 10, "bold"), text="Username:") \
            .grid(row=5, column=0, sticky="e", pady=(40, 5))
        tk.Label(master, bg="#6b73d6", fg="white", font=("Aptos", 10, "bold"), text="Password:") \
            .grid(row=6, column=0, sticky="e", pady=5)

        self.username_entry = tk.Entry(master)
        self.password_entry = tk.Entry(master, show="*")

        self.username_entry.grid(row=5, column=1, pady=(40, 5))
        self.password_entry.grid(row=6, column=1, pady=5)

        return self.username_entry

    def buttonbox(self):
        button_style = {
            "width": 10,
            "font": ("Aptos", 10, "bold"),
            "bg": "#6b73d6",
            "fg": "white",
            "activebackground": "#005f99",
            "activeforeground": "white",
            "bd": 0,
            "relief": "flat",
            "cursor": "hand2"
        }

        box = tk.Frame(self, bg="#d6e2fb")
        tk.Button(box, text="Login", command=self.ok, **button_style).pack(side="left", padx=5, pady=10)
        tk.Button(box, text="Cancel", command=self.cancel, **button_style).pack(side="left", padx=5, pady=10)
        box.pack()

        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)

    def set_geometry(self, size):
        self.update_idletasks()
        w, h = map(int, size.split("x"))
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = (screen_w // 2) - (w // 2)
        y = (screen_h // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def ok(self, event=None):
        self.apply()
        if self.result:
            self.destroy()

    def apply(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Login Failed", "Please enter both username and password.")
            self.result = None
            return

        try:
            with open("credentials/credentials.json", "r") as f:
                users = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Unable to load credentials file: {e}")
            self.result = None
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        for user in users:
            if user["username"] == username:
                if user["password"] == hashed_password:
                    print("[+] Login successful")
                    self.result = {"username": username, "role": user["role"]}
                    return
                else:
                    messagebox.showerror("Login Failed", "Incorrect password.")
                    print("[-] Incorrect password")
                    self.result = None
                    return

        messagebox.showerror("Login Failed", "Username not found.")
        print("[-] Username not found")
        self.result = None


class DashboardWindow(tk.Tk):
    def __init__(self, user_role):
        super().__init__()
        self.user_role = user_role
        self.geometry("650x600")
        self.configure(bg="#ac8aec")
        self._offset_x = 0
        self._offset_y = 0
        self._build_ui()

    def _draw_severity_pie_chart(self, parent_frame):

        try:
            with open("CVE-sol-db/cve-sol-db.json", "r") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load CVE DB: {e}")
            return

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for item in data:
            try:
                score = float(item.get("cvss", "Unknown"))
                if score >= 9.0:
                    counts["Critical"] += 1
                elif score >= 7.0:
                    counts["High"] += 1
                elif score >= 4.0:
                    counts["Medium"] += 1
                elif score >= 0.1:
                    counts["Low"] += 1
                else:
                    counts["Unknown"] += 1
            except ValueError:
                counts["Unknown"] += 1

        filtered_counts = {k: v for k, v in counts.items() if v > 0}
        labels = list(filtered_counts.keys())
        sizes = list(filtered_counts.values())
        colors = ['#d73027', '#fc8d59', '#fee08b', '#d9ef8b', '#999999']

        fig, ax = plt.subplots(figsize=(4, 4), dpi=100)
        fig.patch.set_facecolor('#6b73d6')
        ax.set_facecolor('#6b73d6')
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            colors=colors[:len(labels)],
            startangle=140,
            textprops={'color': 'white', 'fontsize': 8}
        )
        ax.set_title("CVE Severity Breakdown", color="white", fontsize=10)

        chart = FigureCanvasTkAgg(fig, parent_frame)
        chart.get_tk_widget().pack(side="top", fill="both", expand=True)
        chart.draw()

        total_cves = sum(counts.values())

        total_label = tk.Label(
            parent_frame,
            text=f"Total CVEs: {total_cves}",
            font=("Aptos", 10, "bold"),
            fg="#333333",
            bg="#d6e2fb",
            pady=10
        )
        total_label.pack(side="top", anchor="center")

    def _build_ui(self):
        drag_bar = tk.Frame(self, bg="#6b73d6", height=30)
        drag_bar.pack(fill="x")
        drag_bar.bind("<Button-1>", self._click)
        drag_bar.bind("<B1-Motion>", self._drag)

        close_btn = tk.Button(drag_bar, text="✕", command=self.destroy,
                              bg="#6b73d6", fg="white", bd=0,
                              activebackground="#aa0000", activeforeground="white")
        close_btn.pack(side="right", padx=5)

        title = tk.Label(
            self,
            text="🔐 Fairweather Sentinel",
            font=("Aptos", 16, "bold"),
            bg="#ac8aec",
            fg="white",
            anchor="w"
        )
        title.pack(anchor="w", padx=20, pady=(20, 10))

        main_content_frame = tk.Frame(self, bg="#ac8aec")
        main_content_frame.pack(fill="both", expand=True, padx=20, pady=10)


        btn_frame = tk.Frame(main_content_frame, bg="#ac8aec")
        btn_frame.pack(side="left", anchor="n", padx=(0, 20), fill="y")

        button_style = {
            "width": 25,
            "height": 2,
            "font": ("Aptos", 12),
            "bg": "#6b73d6",
            "fg": "white",
            "activebackground": "#005f99",
            "activeforeground": "white",
            "bd": 0,
            "relief": "flat",
            "cursor": "hand2",
            "anchor": "w",
            "justify": "left",
            "padx": 10
        }

        buttons = {
            "Scan for Vulnerabilities": self.open_scanner,
            "Manage Users": self.open_manage_users,
            "Schedule Scan": self._open_schedule_scan,
            "View Reports": self._show_report_window,
            "View Recommendations": self._view_recommendations,
        }

        for label, command in buttons.items():
            btn = tk.Button(btn_frame, text=label, command=command or (lambda: None), **button_style)

            if label == "Manage Users" and self.user_role != "it admin":
                btn.configure(state="disabled")
            if label == "Scan for Vulnerabilities" and self.user_role == "viewer":
                btn.configure(state="disabled")
            if label == "Schedule Scan" and self.user_role == "viewer":
                btn.configure(state="disabled")

            btn.pack(anchor="w", pady=5)

        self.chart_frame = tk.Frame(main_content_frame, bg="#d6e2fb", bd=2, relief="ridge")
        self.chart_frame.pack(side="right", fill="both", expand=True)
        self._draw_severity_pie_chart(self.chart_frame)

    def _click(self, event):
        self._offset_x = event.x
        self._offset_y = event.y

    def _drag(self, event):
        x = self.winfo_pointerx() - self._offset_x
        y = self.winfo_pointery() - self._offset_y
        self.geometry(f"+{x}+{y}")

    def open_scanner(self):
        self.withdraw()
        SentinelGUI().mainloop()
        self.deiconify()

    def open_manage_users(self):
        import tkinter as tk
        from tkinter import ttk, messagebox
        import json, hashlib

        def load_users():
            try:
                with open("credentials/credentials.json", "r") as f:
                    return json.load(f)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load users: {e}")
                return []

        def save_users():
            try:
                with open("credentials/credentials.json", "w") as f:
                    json.dump(users, f, indent=4)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save users: {e}")

        def populate_listbox():
            user_listbox.delete(0, tk.END)
            for user in users:
                user_listbox.insert(tk.END, f"{user['username']} ({user['role']})")

        def on_user_select(event):
            try:
                idx = user_listbox.curselection()[0]
                selected_user = users[idx]
                username_entry.delete(0, tk.END)
                username_entry.insert(0, selected_user["username"])
                role_combo.set(selected_user["role"])
                password_entry.delete(0, tk.END)
                nonlocal selected_index
                selected_index = idx
            except IndexError:
                return

        def update_user():
            if selected_index is None:
                messagebox.showwarning("Warning", "Select a user to update.")
                return
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            role = role_combo.get()
            if not username or not role:
                messagebox.showerror("Input Error", "Username and Role are required.")
                return
            users[selected_index]["username"] = username
            users[selected_index]["role"] = role
            if password:
                users[selected_index]["password"] = hashlib.sha256(password.encode()).hexdigest()
            save_users()
            populate_listbox()
            messagebox.showinfo("Success", "User updated.")

        def add_user():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            role = role_combo.get()
            if not username or not password or not role:
                messagebox.showerror("Input Error", "All fields are required.")
                return
            if any(u["username"] == username for u in users):
                messagebox.showerror("Duplicate", "Username already exists.")
                return
            new_user = {
                "username": username,
                "password": hashlib.sha256(password.encode()).hexdigest(),
                "role": role
            }
            users.append(new_user)
            save_users()
            populate_listbox()
            messagebox.showinfo("Success", "User added.")

        selected_index = None
        users = load_users()

        window = tk.Toplevel(self)
        window.title("Manage Users")
        window.geometry("265x320")
        window.configure(bg="#ac8aec")

        user_listbox = tk.Listbox(window, bg="#d6e2fb")
        user_listbox.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        user_listbox.bind("<<ListboxSelect>>", on_user_select)

        tk.Label(window, text="Username:",
            font=("Aptos", 10, "bold"), fg="white", bg="#6b73d6").grid(row=1, column=0, sticky="e")
        username_entry = tk.Entry(window)
        username_entry.grid(row=1, column=1, padx=10, pady=5)

        tk.Label(window, text="New Password:",
            font=("Aptos", 10, "bold"), fg="white", bg="#6b73d6").grid(row=2, column=0, sticky="e")
        password_entry = tk.Entry(window, show="*")
        password_entry.grid(row=2, column=1, padx=10, pady=5)

        tk.Label(window, text="Role:",
            font=("Aptos", 10, "bold"), fg="white", bg="#6b73d6").grid(row=3, column=0, sticky="e")
        role_combo = ttk.Combobox(window, values=["it admin", "analyst", "viewer"], state="readonly")
        role_combo.grid(row=3, column=1, padx=10, pady=5)

        tk.Button(
            window, text="Update User", command=update_user,
            font=("Aptos", 10, "bold"), fg="white", bg="#6b73d6", activebackground="#b71c1c"
        ).grid(row=4, column=0, pady=10)

        tk.Button(
            window, text="Add New User", command=add_user,
            font=("Aptos", 10, "bold"), fg="white", bg="#6b73d6", activebackground="#b71c1c"
        ).grid(row=4, column=1, pady=10)

        populate_listbox()

    def _open_schedule_scan(self):
        win = tk.Toplevel(self)
        win.title("Schedule Scan")
        win.geometry("350x220")
        win.configure(bg="#ac8aec")

        tk.Label(win, text="Target IP:", bg="#6b73d6").pack(pady=(10, 0))
        ip_entry = tk.Entry(win)
        ip_entry.pack()

        tk.Label(win, text="Start Time (HH:MM 24hr):", bg="#6b73d6").pack(pady=(10, 0))
        time_entry = tk.Entry(win)
        time_entry.pack()

        def schedule():
            ip = ip_entry.get().strip()
            start_time = time_entry.get().strip()

            if not (ip and start_time):
                messagebox.showerror("Error", "All fields are required.")
                return

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                messagebox.showerror("Error", f"'{ip}' is not a valid IP address.")
                return

            try:
                now = datetime.now()
                scheduled_time = datetime.strptime(start_time, "%H:%M")
                scheduled_time = scheduled_time.replace(year=now.year, month=now.month, day=now.day)

                if scheduled_time < now:
                    messagebox.showerror("Error", "Cannot schedule for a past time today.")
                    return

                if scheduled_time.hour == now.hour and scheduled_time.minute == now.minute:
                    messagebox.showerror("Error", "Cannot schedule within the same minute.")
                    return

                schedule_scan(ip, "balanced", start_time)
                messagebox.showinfo("Scheduled", f"Comprehensive scan for {ip} scheduled at {start_time}")
                win.destroy()

            except ValueError:
                messagebox.showerror("Error", "Time must be in HH:MM format.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to schedule: {e}")

        tk.Button(win, text="Schedule", bg="#6b73d6", fg="white", font=("Aptos", 10, "bold"), command=schedule).pack(
            pady=10)

    def _get_cve_description(self, cve_id):
        try:
            parts = cve_id.split('-')
            if len(parts) != 3 or not parts[1].isdigit():
                return f"Invalid CVE format: {cve_id}"

            year = parts[1]
            cve_number = parts[2]

            thousands = str(int(cve_number) // 1000) + "xxx"

            cve_file_path = os.path.join("cves", year, thousands, f"{cve_id}.json")

            if not os.path.exists(cve_file_path):
                return f"CVE file not found: {cve_file_path}"

            with open(cve_file_path, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)

            description = None

            cna_descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
            if cna_descriptions:
                for desc in cna_descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value')
                        break

            if not description:
                legacy_desc_data = (cve_data.get('containers', {})
                                    .get('cna', {})
                                    .get('x_legacyV4Record', {})
                                    .get('description', {})
                                    .get('description_data', []))

                if legacy_desc_data:
                    for desc in legacy_desc_data:
                        if desc.get('lang') in ['en', 'eng']:
                            description = desc.get('value')
                            break

            return description if description else "No description available"

        except Exception as e:
            return f"Error reading CVE {cve_id}: {str(e)}"

    def _extract_cves_from_text(self, text):
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        return re.findall(cve_pattern, text, re.IGNORECASE)

    def _show_report_window(self):
        filepath = filedialog.askopenfilename(
            title="Select Report File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )

        if not filepath:
            return

        if not filepath.lower().endswith(".txt"):
            messagebox.showerror("Invalid File", "Only .txt files are supported for reports.")
            return

        try:
            with open(filepath, 'r') as file:
                lines = file.readlines()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file:\n{e}")
            return

        port_blocks = []
        block = ""
        for line in lines:
            if line.startswith("Port "):
                if block and any("CVE" in l for l in block.splitlines()):
                    port_blocks.append(block)
                block = line
            else:
                block += line
        if block and any("CVE" in l for l in block.splitlines()):
            port_blocks.append(block)

        report_win = tk.Toplevel(self)
        report_win.title("Vulnerability Report – Filtered")
        report_win.geometry("670x600")
        report_win.configure(bg="#1f2a40")

        canvas = tk.Canvas(report_win, bg="#1f2a40", highlightthickness=0)
        scrollbar = tk.Scrollbar(report_win, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#d6e2fb")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        processed_cves = set()

        for block in port_blocks:
            block_cves = self._extract_cves_from_text(block)

            new_cves = [cve for cve in block_cves if cve not in processed_cves]

            if not new_cves:
                continue

            processed_cves.update(new_cves)

            block_frame = tk.Frame(scrollable_frame, bg="#6b73d6", bd=2, relief="groove")
            block_frame.pack(fill="x", padx=10, pady=10, anchor="w")

            port_line = block.strip().splitlines()[0] if block.strip().splitlines() else ""
            if port_line:
                port_label = tk.Label(block_frame, text=port_line, bg="#6b73d6", fg="#ffffff",
                                      anchor="w", justify="left", font=("Aptos", 10, "bold"))
                port_label.pack(anchor="w", padx=5, pady=(5, 2))

            seen_cve_lines = set()

            for line in block.strip().splitlines():
                stripped = line.strip()

                if not stripped or stripped.startswith("Port "):
                    continue

                if "CVE-" in stripped.upper():
                    cves_in_line = self._extract_cves_from_text(stripped)

                    line_has_new_cves = any(cve in new_cves for cve in cves_in_line)
                    if not line_has_new_cves:
                        continue

                    for cve_id in cves_in_line:
                        if cve_id in new_cves:
                            cve_line = f"{cve_id}: {self._get_cve_description(cve_id)}"

                            if cve_line not in seen_cve_lines:
                                seen_cve_lines.add(cve_line)

                                wrapped_lines = textwrap.wrap(cve_line, width=100,
                                                              break_long_words=False, break_on_hyphens=False)
                                for wline in wrapped_lines:
                                    label = tk.Label(block_frame, text=wline, bg="#6b73d6", fg="#e0e0e0",
                                                     anchor="w", justify="left", font=("Aptos", 10))
                                    label.pack(anchor="w", padx=5)
                else:
                    if stripped and stripped not in seen_cve_lines:
                        seen_cve_lines.add(stripped)
                        wrapped_lines = textwrap.wrap(stripped, width=100,
                                                      break_long_words=False, break_on_hyphens=False)
                        for wline in wrapped_lines:
                            label = tk.Label(block_frame, text=wline, bg="#6b73d6", fg="#e0e0e0",
                                             anchor="w", justify="left", font=("Aptos", 10))
                            label.pack(anchor="w", padx=5)

    def _view_recommendations(self):
        report_path = filedialog.askopenfilename(
            title="Select Vulnerability Report",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not report_path:
            return

        if not report_path.lower().endswith(".txt"):
            messagebox.showerror("Invalid File", "Only .txt files are supported for recommendation reports.")
            return

        try:
            with open(report_path, 'r') as report_file:
                report_content = report_file.read()
        except Exception as e:
            messagebox.showerror("Error", f"Unable to read report:\n{e}")
            return

        found_cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', report_content))
        db_folder = "CVE-sol-db"
        db_path = os.path.join(db_folder, "cve-sol-db.json")

        os.makedirs(db_folder, exist_ok=True)

        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as db_file:
                    cve_db = json.load(db_file)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load CVE database:\n{e}")
                return
        else:
            cve_db = []

        cve_lookup = {entry["cve_id"]: entry for entry in cve_db}
        matched = []
        updated = False

        for cve in found_cves:
            if cve in cve_lookup:
                matched.append(cve_lookup[cve])
            else:
                cvss = fetch_cvss_from_nvd(cve)
                solution = fetch_solution_from_groq(cve)
                new_entry = {
                    "cve_id": cve,
                    "cvss_score": cvss,
                    "solution": solution,
                    "cvss": cvss
                }
                matched.append(new_entry)
                cve_db.append(new_entry)
                updated = True

        matched.sort(key=safe_cvss_score, reverse=True)

        if updated:
            try:
                with open(db_path, 'w') as db_file:
                    json.dump(cve_db, db_file, indent=4)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update CVE database:\n{e}")
                return

        if not matched:
            messagebox.showinfo("No Matches", "No CVEs found in report.")
            return

        matched.sort(key=lambda x: x.get("cvss_score", 0.0) or 0.0, reverse=True)

        win = tk.Toplevel(self)
        win.title("CVE Recommendations")
        win.geometry("650x600")
        win.configure(bg="#1f2a40")

        canvas = tk.Canvas(win, bg="#d6e2fb", highlightthickness=0)
        scrollbar = tk.Scrollbar(win, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#d6e2fb")

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for entry in matched:
            frame = tk.Frame(scrollable_frame, bg="#6b73d6", bd=2, relief="groove")
            frame.pack(fill="x", padx=10, pady=10, anchor="w")

            cve_id = entry.get("cve_id", "Unknown")
            cvss = entry.get("cvss", "Unknown")
            solution = entry.get("solution", "No solution available.")

            lines = [
                f"🛡️ CVE ID: {cve_id}",
                f"⭐ CVSS Score: {cvss}",
                f"🛠️ Solution: {solution}"
            ]

            for line in lines:
                wrapped = textwrap.wrap(line, width=100, break_long_words=False, break_on_hyphens=False)
                for wline in wrapped:
                    label = tk.Label(frame, text=wline, bg="#6b73d6", fg="#e0e0e0",
                                     anchor="w", justify="left", font=("Aptos", 10))
                    label.pack(anchor="w", padx=5, pady=1)


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()

    login = LoginDialog(root, title="Login")

    if login.result:
        print("[DEBUG] Login result:", login.result)
        root.destroy()
        app = DashboardWindow(user_role=login.result["role"])
        app.mainloop()
    else:
        print("[-] Login failed or cancelled.")
        sys.exit(0)


