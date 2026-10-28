# Operational Guide & Workaround Manual

## Automated SOC Alert Enrichment & Triage Platform (PGlite WASM Edition)

This guide provides end-to-end instructions for running, configuring, testing, and troubleshooting the platform, including how to integrate external SIEM tools (such as Wazuh), configure Threat Intelligence feeds, utilize the MITRE ATT&CK correlation engine, execute automated SOAR playbooks, investigate indicators with deep CTI links, and generate executive shift handover reports.

---

## Table of Contents
1. [Quick Startup Guide](#1-quick-startup-guide)
2. [Configuration Guide & Environment Variables](#2-configuration-guide--environment-variables)
3. [How to Use the Application & Analyst Workflows](#3-how-to-use-the-application--analyst-workflows)
   - 3.1 [Live Operations Dashboard & Theme Switching](#31-live-operations-dashboard--theme-switching)
   - 3.2 [Correlated Incidents & Lateral Movement Attack Graph](#32-correlated-incidents--lateral-movement-attack-graph)
   - 3.3 [Structured Root Cause & Hypothesis Triage](#33-structured-root-cause--hypothesis-triage)
   - 3.4 [Automated SOAR Playbook Runner](#34-automated-soar-playbook-runner)
   - 3.5 [Interactive IOC Threat Hunting Flyout](#35-interactive-ioc-threat-hunting-flyout)
   - 3.6 [MITRE ATT&CK Enterprise Matrix Heatmap](#36-mitre-attck-enterprise-matrix-heatmap)
   - 3.7 [One-Click Shift Handover & Incident Reports](#37-one-click-shift-handover--incident-reports)
   - 3.8 [Simulating Threat Scenarios](#38-simulating-threat-scenarios)
4. [Wazuh SIEM Integration Guide](#4-wazuh-siem-integration-guide)
5. [Threat Intelligence & Telegram Setup](#5-threat-intelligence--telegram-setup)
6. [PGlite Browser-WASM & Threat Hunting SQL Bookmarks](#6-pglite-browser-wasm--threat-hunting-sql-bookmarks)
7. [Troubleshooting & Common Workarounds](#7-troubleshooting--common-workarounds)

---

## 1. Quick Startup Guide

The platform consists of two cooperating services:
1. **Golang Core Engine** (Runs on port `8080`)
2. **Next.js Operations Dashboard** (Runs on port `3000`)

### Option A: Running on Windows (PowerShell)

#### Terminal 1 — Start the Go Backend:
```powershell
cd D:\SIEM\backend
.\server.exe
```
*(If you want to run directly from Go source: `go run cmd/server/main.go`)*

#### Terminal 2 — Start the Next.js Frontend:
```powershell
cd D:\SIEM\frontend
npm run dev
```

Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

### Option B: Running on Linux / macOS (Bash)

#### Terminal 1 — Backend:
```bash
cd backend
go run cmd/server/main.go
```

#### Terminal 2 — Frontend:
```bash
cd frontend
npm install
npm run dev
```

---

### Option C: Containerized Deployment (Docker Compose)

```bash
cd deployments
docker compose up --build
```

---

## 2. Configuration Guide & Environment Variables

### 2.1 Backend Environment File (`backend/.env`)

Configure `backend/.env` with your settings:

```env
# SERVER CONFIGURATION
PORT=8080
ENV=development
LOG_LEVEL=info
ALLOWED_ORIGINS=http://localhost:3000

# THREAT INTEL API KEYS
# Note: Leave empty to enable the intelligent deterministic simulation fallback!
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=

# TELEGRAM BOT INTEGRATION (Optional)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# ZERO TRUST TUNNELS (Optional)
CF_TUNNEL_TOKEN=
TAILSCALE_AUTH_KEY=
```

> **Smart CTI Fallback Feature**: If you don't provide external API keys, the Go engine automatically applies deterministic threat simulation scores for known attack indicators (e.g., `118.25.6.39`, `198.51.100.42`), so the entire system functions out-of-the-box with zero external dependencies.

---

### 2.2 Core Scoring & Asset Multipliers (`backend/config/config.yaml`)

Edit `backend/config/config.yaml` to adjust threat calculation weights and thresholds:

```yaml
server:
  port: 8080
  env: "development"

scoring:
  weights:
    virustotal: 0.40  # 40% weight
    abuseipdb: 0.35   # 35% weight
    shodan: 0.25      # 25% weight
  thresholds:
    critical: 80.0    # Score >= 80 triggers auto-block containment
    high: 60.0        # Score >= 60 triggers immediate Telegram card
    medium: 30.0      # Score >= 30 flags for analyst review
  default_asset_multiplier: 1.0
  asset_criticality:
    dc-01.domain.corp: 1.5   # Domain Controller: 1.5x score boost
    db-prod.internal: 1.4    # Production Database: 1.4x score boost
    payment-gw: 1.5          # Payment Gateway: 1.5x score boost
    dmz-proxy: 1.1           # DMZ Proxy: 1.1x score boost
    corp-workstation: 1.0    # Standard Host: 1.0x (normal)
```

---

### 2.3 Frontend Configuration (`frontend/.env.local`)

By default, the dashboard connects to `http://localhost:8080` and `ws://localhost:8080/ws/alerts`. If running on remote hosts or behind a reverse proxy:

```env
NEXT_PUBLIC_API_URL=http://your-server-ip:8080/api/v1
NEXT_PUBLIC_WS_URL=ws://your-server-ip:8080/ws/alerts
```

---

## 3. How to Use the Application & Analyst Workflows

### 3.1 Live Operations Dashboard & Theme Switching
1. Navigate to **[http://localhost:3000](http://localhost:3000)**.
2. In the top navigation bar, verify the operational badges:
   - **Go Core WS: CONNECTED** (green pulsating dot).
   - **PGlite WASM Active** (indicates browser PostgreSQL database is online).
3. The KPI cards show **Total Ingested**, **Critical Threats**, **High Severity**, **Contained / Triaged**, and **Average Risk Score**.
4. Click the **Sun / Moon Toggle** in the top right header to switch between Dark and Light mode. The choice is stored in `localStorage` with zero-flicker reload.

---

### 3.2 Correlated Incidents & Lateral Movement Attack Graph
Click the **"Incidents"** tab to view alerts correlated by primary adversary IP or targeted asset into unified campaigns (`INC-XXXXXX`):
- **Adversary Pivot Summary**: Displays initial access timestamp, last seen telemetry, highest threat tier, and overall hypothesis summary.
- **Visual Attack Graph**: Expand any incident to reveal the interactive lateral movement flow:
  $$\text{Attacker IP} \xrightarrow{\text{PIVOT}} \text{Target Asset} \xrightarrow{\text{PIVOT}} \text{Internal Crown Jewel}$$
- Each node visualizes the chronological stage number, calculated score, MITRE tactic, and endpoint pivot edge.

---

### 3.3 Structured Root Cause & Hypothesis Triage
Inside each alert card:
1. Expand the **"Root Cause & Hypothesis Analysis"** accordion.
2. Review the structured intelligence:
   - **CAUSE**: Primary deterministic vector (e.g., C2 beaconing, credential stuffing, privilege escalation).
   - **HYPOTHESES TABLE**: Open, confirmed, or refuted possibilities with supporting and contradicting evidence.
   - **WHAT WOULD SETTLE IT**: Exact forensic commands to verify the vector (e.g., `netstat -ano`, inspect process memory for injected DLLs).
   - **WHAT TO DO**: Recommended next check and containment action.
3. Select an active hypothesis from the **"Link Action to Hypothesis"** dropdown.
4. Add analyst operational notes and click:
   - **🚫 Block IP**: Drops inbound/outbound packets and flags the alert `CONTAINED`.
   - **🛡️ Isolate Host**: Sever endpoint network adapter and flags the alert `CONTAINED`.
   - **✅ Mark Triaged**: Verifies remediation and marks the alert `TRIAGED`.
   - **❌ Dismiss**: Flags false-positive and marks the alert `DISMISSED`.
5. Every action and hypothesis selection is recorded to both the Go backend audit log and the browser-native `triage_actions` table.

---

### 3.4 Automated SOAR Playbook Runner
When an analyst clicks **"🚫 Block IP"** or **"🛡️ Isolate Host"**:
- A slide-out **SOAR Playbook Drawer** automatically opens.
- The system animates and executes multi-step multi-vendor containment tasks:
  - *Query Threat Intelligence APIs* (AbuseIPDB, VirusTotal, Shodan).
  - *Inject Drop Rules into Edge Firewalls* (Palo Alto / Cisco ASA / pfSense).
  - *Push IOC into Internal SIEM & Core DNS Sinkhole Watchlists*.
  - *Sever EDR Network Adapter & Terminate Rogue Process Trees*.
  - *Trigger Volatile RAM Memory Dumps for Memory Forensics*.
  - *Broadcast Incident Briefings to Telegram / SecOps Channels*.
- Each step displays live CLI console output and status badges.

---

### 3.5 Interactive IOC Threat Hunting Flyout
On any alert card or incident timeline, click any indicator badge (e.g., `IP: 118.25.6.39`, `HASH: 7a8b...`, or `DOMAIN: ...`):
- Opens the **IOC Threat Hunting Drawer**.
- **External CTI Deep Links**: Direct one-click links to **VirusTotal**, **AbuseIPDB**, and **Shodan**.
- **Network Attributes**: Displays Country origin, Autonomous System (ASN), city, and coordinates.
- **One-Click Firewall Rule Generator**:
  - `iptables -A INPUT -s <IP> -j DROP`
  - `Cisco ASA`: `access-list OUTSIDE_BLOCK extended deny ip host <IP> any`
  - `Palo Alto`: `set address block_<IP> ip-netmask <IP>/32`
  - `PowerShell`: `New-NetFirewallRule -DisplayName "SOC_Block_<IP>" -Direction Inbound -Action Block -RemoteAddress <IP>`
- **Correlated Historical Alerts**: Instantly queries your local PGlite WASM database for all alerts that have ever matched this indicator.

---

### 3.6 MITRE ATT&CK Enterprise Matrix Heatmap
Click the **"MITRE ATT&CK Matrix"** tab:
- Visualizes enterprise kill-chain tactics across all 13 phases (`Reconnaissance`, `Resource Development`, `Initial Access`, `Execution`, `Persistence`, `Privilege Escalation`, `Defense Evasion`, `Credential Access`, `Discovery`, `Lateral Movement`, `Collection`, `Command and Control`, `Impact`).
- Cells glow according to alert severity density (Green $\to$ Amber $\to$ Red).
- Displays technique IDs (e.g., `T1071`, `T1486`, `T1110`, `T1190`, `T1046`) and affected asset counts.

---

### 3.7 One-Click Shift Handover & Incident Reports
Click the **"Generate Handover Report"** button in the dashboard header:
- Automatically collates all active incidents, MITRE ATT&CK kill-chain coverage, root cause evidence, and analyst audit actions into a comprehensive **TLP:AMBER** briefing.
- Features:
  - **Download Markdown (`.md`)**: Full report ready for Jira, Confluence, or GitHub issue tracking.
  - **Print / Save as PDF**: Opens a clean, professional print stylesheet with header cards and formatted tables.

---

### 3.8 Simulating Threat Scenarios
Click the **"Simulate Attack"** button in the dashboard header to inject test security events:
- **Cobalt Strike C2 Beacon**: External IP targeting a Domain Controller (triggers automated containment).
- **Ransomware Shadow Deletion**: `vssadmin.exe` execution with malicious file hash on a production database.
- **Log4j RCE (CVE-2021-44228)**: JNDI injection payload targeting a payment gateway.
- **Distributed SSH Brute Force**: Repeated failed logins from a reputation-flagged IP.
- **SYN Stealth Port Scan**: Reconnaissance port sweep.

> **Offline Dual-Mode Execution**: The simulation first attempts to ingest via the Go backend (`POST /api/v1/alerts/ingest`). If the Go backend is stopped, it automatically injects directly into the browser's PGlite WASM engine, allowing offline testing and demonstrations.

---

## 4. Wazuh SIEM Integration Guide

You can connect your live Wazuh Manager instance to push alerts automatically to this platform.

### Step 4.1: Add Custom Integration in Wazuh Manager

1. Open `/var/ossec/etc/ossec.conf` on your Wazuh Manager:
```xml
<ossec_config>
  <integration>
    <name>custom-soar</name>
    <hook_url>http://<YOUR_PLATFORM_IP>:8080/api/v1/alerts/ingest</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

### Step 4.2: Create the Wazuh Integration Script

Create the file `/var/ossec/integrations/custom-soar`:

```python
#!/usr/bin/env python3
import sys
import json
import urllib.request

alert_file = sys.argv[1]
hook_url = sys.argv[3]

with open(alert_file, 'r') as f:
    alert_json = json.load(f)

# Extract indicators and normalize payload for Go Core
rule = alert_json.get("rule", {})
data = alert_json.get("data", {})
syscheck = alert_json.get("syscheck", {})

payload = {
    "source": "Wazuh-SIEM",
    "event_type": rule.get("description", "Generic Wazuh Alert"),
    "severity": "CRITICAL" if rule.get("level", 0) >= 12 else ("HIGH" if rule.get("level", 0) >= 8 else "MEDIUM"),
    "src_ip": data.get("srcip", ""),
    "dst_ip": data.get("dstip", ""),
    "file_hash": syscheck.get("sha256_after", ""),
    "metadata": {
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "agent": alert_json.get("agent", {})
    }
}

req = urllib.request.Request(
    hook_url,
    data=json.dumps(payload).encode('utf-8'),
    headers={"Content-Type": "application/json"}
)

try:
    urllib.request.urlopen(req, timeout=5)
except Exception as e:
    sys.exit(1)
```

Make the script executable and set ownership:
```bash
chmod 750 /var/ossec/integrations/custom-soar
chown root:wazuh /var/ossec/integrations/custom-soar
systemctl restart wazuh-manager
```

---

## 5. Threat Intelligence & Telegram Setup

### 5.1 Threat Intelligence API Keys
To connect live feeds, register for free API keys:
1. **VirusTotal**: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
2. **AbuseIPDB**: [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register)
3. **Shodan**: [https://account.shodan.io/register](https://account.shodan.io/register)

Place them in `backend/.env` and restart the backend.

### 5.2 Telegram Bot Setup
1. Open Telegram and search for `@BotFather`. Send `/newbot` and follow instructions to obtain your **Bot Token**.
2. Create a channel or group, add your bot, and obtain your **Chat ID** (e.g., via `@userinfobot` or checking `https://api.telegram.org/bot<TOKEN>/getUpdates`).
3. Add `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` to `backend/.env`.
4. Alerts with score $\ge 60$ will dispatch inline cards with clickable triage buttons.

---

## 6. PGlite Browser-WASM & Threat Hunting SQL Bookmarks

### 6.1 What is PGlite?
PGlite is a complete **PostgreSQL engine compiled to WebAssembly (WASM)** that runs inside the analyst's browser.
- **Storage**: Persists data inside `idb://soc-alerts-db` (IndexedDB) with memory fallback.
- **Zero Latency**: Client queries execute in < 2ms without round-trips to an external database server.
- **Offline Capable**: The database and audit history remain intact across page refreshes.

### 6.2 Threat Hunting SQL Bookmarks
Click the **"SQL Console"** button in the dashboard header:
- Pre-built bookmarks allow 1-click execution:
  - **All Alerts By Score**:
    ```sql
    SELECT alert_uuid, source, calculated_score, status FROM alerts ORDER BY calculated_score DESC;
    ```
  - **Multi-CTI Corroboration Stats**:
    ```sql
    SELECT provider, COUNT(*) as hit_count, ROUND(AVG(normalized_score), 2) as avg_cti_score FROM enrichment_data GROUP BY provider;
    ```
  - **Hunt: High-Frequency IOCs**:
    ```sql
    SELECT i.ioc_value, i.ioc_type, COUNT(DISTINCT a.alert_uuid) as hit_count, MAX(a.calculated_score) as max_score 
    FROM alert_iocs i 
    JOIN alerts a ON i.alert_uuid = a.alert_uuid 
    GROUP BY i.ioc_value, i.ioc_type 
    ORDER BY hit_count DESC;
    ```
  - **Hunt: Contained vs Open Incidents**:
    ```sql
    SELECT status, COUNT(*) as count, ROUND(AVG(calculated_score), 1) as avg_score FROM alerts GROUP BY status;
    ```
  - **Triage Audit Logs & Hypotheses**:
    ```sql
    SELECT alert_uuid, actor, action_taken, hypothesis_selected, performed_at FROM triage_actions ORDER BY performed_at DESC;
    ```
- **Export CSV Button**: Instantly export query result sets to `.csv` for external analysis in Excel or Jupyter Notebooks.

---

## 7. Troubleshooting & Common Workarounds

### Issue 1: Port `8080` or `3000` is Already in Use
**Workaround**:
Find and terminate the process holding the port:
```powershell
# Check what is using port 8080:
Get-Process -Id (Get-NetTCPConnection -LocalPort 8080).OwningProcess
# Terminate:
Stop-Process -Id <PID> -Force
```
Or override the port in `backend/.env` (`PORT=8085`) and `frontend/.env.local`.

### Issue 2: WebSocket Connection Shows "DISCONNECTED"
**Workaround**:
1. Confirm the backend is running (`curl.exe http://localhost:8080/health`).
2. The frontend uses decoupled listeners with exponential backoff and random jitter (capped at 10 retries). If you start the backend after the frontend, click the **"Refresh"** button on the dashboard to immediately re-establish the connection.
3. If accessing the frontend from a different machine or IP, ensure `NEXT_PUBLIC_WS_URL=ws://<BACKEND_IP>:8080/ws/alerts` is set in `frontend/.env.local`.

### Issue 3: PGlite Browser Splash Screen Hang / IndexedDB Lock
**Workaround**:
If multiple browser tabs open the dashboard simultaneously, an `IndexedDB` lock conflict may occur. The platform implements an automatic 4-second timeout that gracefully falls back to an in-memory PostgreSQL WASM engine, ensuring the dashboard never freezes on startup.

### Issue 4: External CTI API Rate Limits
**Workaround**:
Free CTI tiers typically allow limited queries (e.g., VirusTotal 4 req/min). If an external query fails or times out, the platform catches the error gracefully, returns `0` score for that specific provider without failing the pipeline, and processes the remaining providers within the 2500ms context deadline.

### Issue 5: Simulations When Go Backend is Stopped
**Workaround**:
If testing the UI without running the Golang backend, click **"Simulate Attack"** $\to$ select any scenario $\to$ click **"Simulate"**. The frontend automatically detects the absent Go server and injects the attack scenario directly into the browser's PGlite WASM database, immediately updating all metric cards, incidents, and MITRE heatmaps.
