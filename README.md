# AegisVersion-Sentinel 🛡️

**AegisVersion-Sentinel** is an automated Python-based auditing tool designed to monitor and compare network infrastructure firmware versions. It proactively scrapes manufacturer data to recommend maintenance and evolution paths for critical network assets.

---

## 🚀 Key Features

* **Multi-Vendor Support**: Unified auditing for Fortinet (FortiOS/FortiManager), Cisco (IOS-XE/NX-OS), and F5 (BIG-IP).
* **Intelligent Branch Mapping**: Automatically distinguishes between a **Maintenance** patch (same branch stability) and an **Evolution** path (next generation release).
* **Live Web Scraping**: Fetches the latest PSIRT and firmware data directly from manufacturer portals.
* **"Mature" Release Prioritization**: Specifically targets versions marked as "Mature" (M) for production environments.
* **Pro HTML Reporting**: Generates a clean, color-coded executive report with status indicators (OK vs. Upgrade Needed).

---

## 🛠️ How It Works



The script operates in three distinct phases:

1. **Ingestion**: Loads the device inventory including current hardware and firmware versions.
2. **Intelligence Gathering**: Connects to vendor sites (e.g., FortiGuard, Cisco Software Checker) to identify the highest stable releases.
3. **Gap Analysis**: Compares the "Current" vs. "Recommended" versions using advanced version-tuple parsing to determine the upgrade status.

---

## 📋 Prerequisites

* **Python 3.8+**
* **Library**: `requests` (to handle HTTP connections)

```bash
pip install requests

---
