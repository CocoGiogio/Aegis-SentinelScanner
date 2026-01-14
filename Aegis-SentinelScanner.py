import requests
import re
from datetime import datetime

# --- INVENTORY ---
INVENTORY = [
    # Fortinet - Various active branches
    {"Name": "US-EDGE-FW01", "Hardware": "FortiGate 100F", "Current": "FortiOS 7.0.12M"},
    {"Name": "EU-DC-CLUSTER-A", "Hardware": "FortiGate 1500D", "Current": "FortiOS 7.2.5M"},
    {"Name": "LAB-SANDBOX-FG", "Hardware": "FortiGate VM64-KVM", "Current": "FortiOS 6.4.14M"},
    
    # FortiManager - Different branch
    {"Name": "GLOBAL-FMG-01", "Hardware": "FortiManager 3000G", "Current": "FortiManager 7.4.2"},
    
    # Cisco Catalyst - Diverse IOS-XE releases
    {"Name": "FLOOR1-ASW-01", "Hardware": "Cisco Catalyst 9300-48P", "Current": "IOS-XE 17.6.5"},
    {"Name": "CORE-VSS-STACK", "Hardware": "Cisco Catalyst 9500", "Current": "IOS-XE 17.3.3"},
    
    # Cisco Nexus - NX-OS releases
    {"Name": "LEAF-POD1-101", "Hardware": "Cisco Nexus 93180YC-EX", "Current": "NX-OS 9.3(10)"},
    {"Name": "SPINE-CORE-201", "Hardware": "Cisco Nexus 9504", "Current": "NX-OS 10.2(3)M"},
    
    # F5 BIG-IP - Older and modern branches
    {"Name": "PROD-LTM-LB01", "Hardware": "F5 BIG-IP i5800", "Current": "BIG-IP 15.1.8"},
    {"Name": "EDGE-WAF-02", "Hardware": "F5 BIG-IP i2800", "Current": "BIG-IP 16.1.3"},
    {"Name": "GLOBAL-GTM-VE", "Hardware": "F5 BIG-IP VE-1G", "Current": "BIG-IP 17.0.0"}
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
