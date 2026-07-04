import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import os

EVE_FILE = "/var/log/suricata/eve.json"
INTERFACE = "eth0"
REFRESH_TIME = 2000  # 2 seconds

class SuricataGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Suricata IDS/IPS - Real Time Monitor")
        self.root.geometry("1000x500")

        self.create_widgets()
        self.auto_refresh()

    def create_widgets(self):
        top = tk.Frame(self.root)
        top.pack(fill="x")

        tk.Label(top, text="Interface: eth0", font=("Arial", 10, "bold")).pack(side="left", padx=5)

        tk.Button(top, text="Start Suricata", command=self.start_suricata).pack(side="left", padx=5)
        tk.Button(top, text="Stop Suricata", command=self.stop_suricata).pack(side="left", padx=5)

        tk.Label(top, text="Min Severity (1-4):").pack(side="left", padx=5)
        self.severity = tk.IntVar(value=1)
        tk.Entry(top, width=3, textvariable=self.severity).pack(side="left")

        columns = ("time", "src", "sport", "dst", "dport", "sev", "msg")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=120)

        self.tree.column("msg", width=300)
        self.tree.pack(fill="both", expand=True)

    def start_suricata(self):
        try:
            subprocess.Popen(
                ["sudo", "suricata", "-i", INTERFACE, "-c", "/etc/suricata/suricata.yaml"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            messagebox.showinfo("Success", "Suricata Started on eth0")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def stop_suricata(self):
        subprocess.call(["sudo", "pkill", "suricata"])
        messagebox.showinfo("Stopped", "Suricata Stopped")

    def read_alerts(self):
        if not os.path.exists(EVE_FILE):
            return

        self.tree.delete(*self.tree.get_children())

        try:
            with open(EVE_FILE, "r") as f:
                for line in f.readlines()[-200:]:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        alert = data["alert"]
                        if alert["severity"] >= self.severity.get():
                            self.tree.insert("", "end", values=(
                                data["timestamp"],
                                data["src_ip"],
                                data.get("src_port", ""),
                                data["dest_ip"],
                                data.get("dest_port", ""),
                                alert["severity"],
                                alert["signature"]
                            ))
        except:
            pass

    def auto_refresh(self):
        self.read_alerts()
        self.root.after(REFRESH_TIME, self.auto_refresh)


if __name__ == "__main__":
    root = tk.Tk()
    app = SuricataGUI(root)
    root.mainloop()

