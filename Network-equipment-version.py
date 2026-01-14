import requests
import re
import urllib.parse

inventory = [
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

urls = {
    "Cisco Nexus": "https://sec.cloudapps.cisco.com/security/center/softwarechecker.x?productSelected={product}&versionNamesSelected={version}&selectedMethod=A",
    "Cisco Catalyst": "https://sec.cloudapps.cisco.com/security/center/softwarechecker.x?productSelected={product}&versionNamesSelected={version}&selectedMethod=A",
    "FortiGate": "https://www.fortiguard.com/psirt?filter=1&product=FortiOS-6K7K%2CFortiOS&version={version}",
    "FortiManager": "https://www.fortiguard.com/psirt?filter=1&product=FortiManager&version={version}",
    "F5 BIG-IP": "https://my.f5.com/manage/s/article/K33062581"
}

fallback = {
    "Cisco Nexus": "NX-OS 10.4(6)M",
    "Cisco Catalyst": "IOS XE 17.9.6a",
    "FortiGate": "FortiOS 7.4.8",
    "FortiManager": "FortiManager 7.4.7",
    "F5 BIG-IP": "BIG-IP 17.5.1"
}

def fetch_recommended(url, pattern, default):
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        text = " ".join(resp.text.split())
        matches = re.findall(pattern, text)
        if not matches:
            return default
        def version_key(v):
            nums = re.findall(r'\d+', v)
            return tuple(int(n) for n in nums)
        best = max(matches, key=version_key)
        return best
    except Exception:
        return default

def parse_version(s):
    nums = re.findall(r'\d+', s)
    return tuple(int(n) for n in nums) if nums else ()

recommended_versions = {
    "Cisco Nexus": fetch_recommended(urls["Cisco Nexus"].format(product="nx-os", version=""), r"\d+\.\d+\(\d+\)M", fallback["Cisco Nexus"]),
    "Cisco Catalyst": fetch_recommended(urls["Cisco Catalyst"].format(product="ios_xe", version=""), r"\d+\.\d+\.\d+[a-z]?", fallback["Cisco Catalyst"]),
    "FortiGate": fetch_recommended(urls["FortiGate"].format(version=""), r"\d+\.\d+\.\d+", fallback["FortiGate"]),
    "FortiManager": fetch_recommended(urls["FortiManager"].format(version=""), r"\d+\.\d+\.\d+", fallback["FortiManager"]),
    "F5 BIG-IP": fetch_recommended(urls["F5 BIG-IP"], r"BIG-IP\s*\d+(?:\.\d+)+", fallback["F5 BIG-IP"])
}

def extract_version_token(s):
    # extrait un token de version utilisable dans les URLs (ex: 17.9.4 ou 10.3(6) ou 7.4.7)
    if not s:
        return ""
    # cherche d'abord pattern comme 10.3(6)
    m = re.search(r'\d+\.\d+\(\d+\)', s)
    if m:
        return m.group(0)
    # sinon cherche séquence classique 1.2.3...
    m = re.search(r'\d+(?:\.\d+)+', s)
    return m.group(0) if m else ""

def fetch_cves_from_url(url):
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        text = resp.text
        # recherche des CVE
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, flags=re.IGNORECASE)
        cves = sorted(set([cve.upper() for cve in cves]))
        return cves
    except Exception:
        return None

def get_vulnerabilities(hw, current):
    token = extract_version_token(current)
    if not token:
        return "Unknown"
    # Cisco (Catalyst/Nexus)
    if "Cisco Catalyst" in hw or "Cisco Nexus" in hw:
        product = "ios_xe" if "Catalyst" in hw else "nx-os"
        url = urls["Cisco Catalyst"].format(product=product, version=urllib.parse.quote_plus(token))
        cves = fetch_cves_from_url(url)
        if cves is None:
            return "Unknown"
        return ", ".join(cves) if cves else "None found"
    # FortiGate
    if "FortiGate" in hw:
        # use FortiOS product query as provided
        url = urls["FortiGate"].format(version=urllib.parse.quote_plus(token))
        cves = fetch_cves_from_url(url)
        if cves is None:
            return "Unknown"
        return ", ".join(cves) if cves else "None found"
    # FortiManager
    if "FortiManager" in hw:
        url = urls["FortiManager"].format(version=urllib.parse.quote_plus(token))
        cves = fetch_cves_from_url(url)
        if cves is None:
            return "Unknown"
        return ", ".join(cves) if cves else "None found"
    # F5 BIG-IP and others: no scraping implemented for F5 in this script
    return "Not Supported"

results = []
for item in inventory:
    hw = item["Hardware"]
    current = item["Current"]
    if "Cisco Nexus" in hw:
        recommended = recommended_versions["Cisco Nexus"]
    elif "Cisco Catalyst" in hw:
        recommended = recommended_versions["Cisco Catalyst"]
    elif "FortiGate" in hw:
        recommended = recommended_versions["FortiGate"]
    elif "FortiManager" in hw:
        recommended = recommended_versions["FortiManager"]
    elif "F5 BIG-IP" in hw:
        recommended = recommended_versions["F5 BIG-IP"]
    else:
        recommended = "Not Found"

    cv_t = parse_version(current)
    rv_t = parse_version(recommended)

    if not cv_t or not rv_t:
        status = "Unknown"
    else:
        if cv_t == rv_t:
            status = "OK"
        elif cv_t < rv_t:
            status = "Upgrade Needed"
        else:
            status = "Current newer than recommended"

    vulns = get_vulnerabilities(hw, current)

    results.append({
        "Name": item["Name"],
        "Model": hw,
        "Current Version": current,
        "Recommended Version": recommended,
        "Status": status,
        "Vulnerabilities": vulns
    })

# Génération HTML
html_rows = []
for r in results:
    if r["Status"] == "OK":
        color = "#d1ffd1"
    elif r["Status"] == "Upgrade Needed":
        color = "#ffd1d1"
    elif r["Status"] == "Current newer than recommended":
        color = "#fff0c2"
    else:
        color = "#f0f0f0"
    vuln_cell = r["Vulnerabilities"]
    # échappement minimal pour les cellules (on suppose pas de HTML malveillant dans les CVE)
    row = (
        f"<tr style='background:{color};'>"
        f"<td>{r['Name']}</td>"
        f"<td>{r['Model']}</td>"
        f"<td>{r['Current Version']}</td>"
        f"<td>{r['Recommended Version']}</td>"
        f"<td>{r['Status']}</td>"
        f"<td>{vuln_cell}</td>"
        f"</tr>"
    )
    html_rows.append(row)

html_content = f"""
<html><head><meta charset='utf-8'><title>Rapport</title></head><body>
<h1>Rapport versions recommandées</h1>
<table border='1' style='border-collapse:collapse;width:100%;'>
<tr><th>Name</th><th>Model</th><th>Current</th><th>Recommended</th><th>Status</th><th>Vulnerabilities</th></tr>
{''.join(html_rows)}
</table></body></html>
"""

with open("PYTHON/VERSION_SCANNER/report_scraping.html", "w", encoding="utf-8") as f:
    f.write(html_content)
print("Rapport généré : PYTHON/VERSION_SCANNER/report_scraping.html")
