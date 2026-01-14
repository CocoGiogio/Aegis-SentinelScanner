import requests
import re
from datetime import datetime

# --- INVENTORY ---
INVENTORY = [
    {"Name": "C5FIRSIT01", "Hardware": "FortiGate 61E", "Current": "FortiOS 7.4.7M"},
    {"Name": "C6FIRSIT01", "Hardware": "FortiGate 61E", "Current": "FortiOS 7.4.7M"},
    {"Name": "FW-MAIN-ONEDC-1", "Hardware": "FortiGate 1100E", "Current": "FortiOS 7.4.7M"},
    {"Name": "FW-MAIN-ONEDC-2", "Hardware": "FortiGate 1100E", "Current": "FortiOS 7.4.7M"},
    {"Name": "FW-EDGE-ONEDC-1", "Hardware": "FortiGate 200F", "Current": "FortiOS 7.4.7M"},
    {"Name": "FW-EDGE-ONEDC-2", "Hardware": "FortiGate 200F", "Current": "FortiOS 7.4.7M"},
    {"Name": "FORTIMANAGER", "Hardware": "FortiManager VM64", "Current": "FortiManager 7.6.4"},
    {"Name": "C5_RV_SW01", "Hardware": "Cisco Catalyst 9410R", "Current": "IOS-XE 17.9.4"},
    {"Name": "C6_RV_SW01", "Hardware": "Cisco Catalyst 9410R", "Current": "IOS-XE 17.9.4"},
    {"Name": "CS-ONEDC-1", "Hardware": "Cisco Nexus 93240YC-FX2", "Current": "NX-OS 10.3(6)(M)"},
    {"Name": "CS-ONEDC-1-spare", "Hardware": "Cisco Nexus 93240YC-FX2", "Current": "NX-OS 10.4(5)(M)"},
    {"Name": "CS-ONEDC-2", "Hardware": "Cisco Nexus 93240YC-FX2", "Current": "NX-OS 10.3(6)(M)"},
    {"Name": "CS-ONEDC-2-spare", "Hardware": "Cisco Nexus 93240YC-FX2", "Current": "NX-OS 10.4(5)(M)"},
    {"Name": "RP-ONEDC-1", "Hardware": "F5 BIG-IP VE-200M", "Current": "BIG-IP 17.1.3"},
    {"Name": "RP-ONEDC-2", "Hardware": "F5 BIG-IP VE-200M", "Current": "BIG-IP 17.1.3"},
]

class InfrastructureAudit:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        self.cache = {}

    def to_tuple(self, v):
        nums = re.findall(r'\d+', str(v))
        return tuple(int(n) for n in nums) if nums else (0, 0, 0)

    def fetch_fortinet_versions(self, product):
        url = f"https://www.fortiguard.com/psirt?product={product}"
        print(f"[FETCH] Accessing Fortinet PSIRT for {product}...")
        try:
            resp = self.session.get(url, timeout=15)
            # Targeting 7.x.x versions
            found = re.findall(r'\b(7\.[0-6]\.[0-9])\b', resp.text)
            versions = sorted(list(set(found)), key=self.to_tuple, reverse=True)
            print(f"[DEBUG] Found {len(versions)} versions for {product}.")
            return versions
        except Exception as e:
            print(f"[ERROR] Connection failed for Fortinet: {e}")
            return []

    def get_recommendations(self, hw, current):
        curr_t = self.to_tuple(current)
        
        # --- FORTINET LOGIC ---
        if "Forti" in hw:
            key = "FortiOS" if "Gate" in hw else "FortiManager"
            if key not in self.cache:
                self.cache[key] = self.fetch_fortinet_versions(key)
            
            data = self.cache[key]
            maint_v = next((v for v in data if self.to_tuple(v)[:2] == curr_t[:2]), "7.4.8")
            evo_v = next((v for v in data if self.to_tuple(v)[:2] > curr_t[:2]), "7.6.4")
            
            # Suffix (M) only for FortiOS
            suffix = " (M)" if "Gate" in hw else ""
            return f"{maint_v}{suffix}", f"{evo_v}{suffix}"

        # --- CISCO CATALYST (IOS-XE) ---
        if "Catalyst" in hw:
            # Current branch is 17.9.x, Next stable is 17.12.x
            return "17.9.6a", "17.12.4"

        # --- CISCO NEXUS (NX-OS) ---
        if "Nexus" in hw:
            # (M) is a standard suffix for Nexus Mature releases
            return "10.4(6)M", "10.5(1)M"

        # --- F5 BIG-IP ---
        if "BIG-IP" in hw:
            # If current is 17.1.3, Maintenance is latest of 17.1 branch, Evolution is 18.x or next major
            return "17.1.4", "18.1.0"
        
        return "N/A", "N/A"

    def run(self):
        print("="*60)
        print(f"STARTING INFRASTRUCTURE AUDIT - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("="*60)
        results = []
        for item in INVENTORY:
            maint, evo = self.get_recommendations(item["Hardware"], item["Current"])
            v_curr = self.to_tuple(item["Current"])
            v_maint = self.to_tuple(maint)
            
            # Logic: If current version < maintenance version -> Upgrade Needed
            status = "OK" if v_curr >= v_maint else "Upgrade Needed"
            
            # Edge case for FortiManager already on latest
            if "FortiManager" in item["Hardware"] and "7.6.4" in item["Current"]:
                status = "OK"
                maint = "7.6.4"
                evo = "N/A"

            results.append({**item, "maint": maint, "evo": evo, "status": status})
            print(f"[DONE] {item['Name']} processed.")
        return results

def generate_report(data):
    rows = ""
    for r in data:
        status_color = "#dc2626" if r["status"] == "Upgrade Needed" else "#16a34a"
        bg_color = "#fff5f5" if r["status"] == "Upgrade Needed" else "#f0fff4"
        rows += f"""<tr style="background:{bg_color};">
            <td style="padding:12px; font-weight:bold;">{r['Name']}</td>
            <td>{r['Hardware']}</td>
            <td><code>{r['Current']}</code></td>
            <td style="color:#2563eb; font-weight:bold;">{r['maint']}</td>
            <td style="color:#7c3aed;">{r['evo']}</td>
            <td style="color:{status_color}; font-weight:bold;">{r['status']}</td>
        </tr>"""

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Infrastructure Audit Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#f1f5f9; padding:40px; color:#1e293b; }}
            .container {{ max-width: 1200px; margin: auto; background:white; padding:25px; border-radius:12px; box-shadow:0 10px 15px -3px rgba(0,0,0,0.1); }}
            table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
            th {{ background:#1e293b; color:white; padding:12px; text-align:left; font-size:12px; text-transform:uppercase; }}
            td {{ border-bottom: 1px solid #e2e8f0; font-size:14px; padding:10px; }}
            h2 {{ margin-top:0; color:#0f172a; }}
            .info {{ color:#64748b; font-size:14px; margin-bottom:20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Infrastructure Firmware Audit Report</h2>
            <div class="info">Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M')}</div>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>Hardware Model</th>
                        <th>Current Version</th>
                        <th>Maintenance (Same Branch)</th>
                        <th>Evolution (Next Gen)</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </body>
    </html>
    """
    
    filename = "infra_audit_report.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n[FINISH] Audit complete. Report generated: {filename}")

if __name__ == "__main__":
    audit = InfrastructureAudit()
    final_results = audit.run()
    generate_report(final_results)
