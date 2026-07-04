import json
import os

EVE_FILE = "/var/log/suricata/eve.json"

def read_alerts_from_eve(severity_level):
    """
    Reads Suricata eve.json and returns parsed events
    Supports:
    - Alerts (attacks)
    - SSH, FTP, Telnet connections
    """

    events = []

    if not os.path.isfile(EVE_FILE):
        return events

    try:
        with open(EVE_FILE, "r") as file:
            lines = file.readlines()[-300:]

        for line in lines:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = data.get("event_type")

            # =========================
            # ATTACK ALERTS
            # =========================
            if event_type == "alert":
                alert = data.get("alert", {})
                severity = alert.get("severity", 4)

                if severity <= severity_level:
                    events.append({
                        "time": data.get("timestamp", ""),
                        "src": data.get("src_ip", ""),
                        "sport": data.get("src_port", ""),
                        "dst": data.get("dest_ip", ""),
                        "dport": data.get("dest_port", ""),
                        "sev": severity,
                        "msg": alert.get("signature", "Unknown Alert")
                    })

            # =========================
            # CONNECTION EVENTS
            # =========================
            elif event_type in ("ssh", "ftp", "telnet"):
                events.append({
                    "time": data.get("timestamp", ""),
                    "src": data.get("src_ip", ""),
                    "sport": data.get("src_port", ""),
                    "dst": data.get("dest_ip", ""),
                    "dport": data.get("dest_port", ""),
                    "sev": "INFO",
                    "msg": f"{event_type.upper()} connection detected"
                })

    except Exception:
        pass

    return events

