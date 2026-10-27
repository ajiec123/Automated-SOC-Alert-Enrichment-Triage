# Operational Guide & Workaround Manual

## Automated SOC Alert Enrichment & Triage Platform (PGlite WASM Edition)

This guide provides end-to-end instructions for running, configuring, testing, and troubleshooting the platform, including how to integrate external SIEM tools (such as Wazuh) and configure Threat Intelligence feeds.

---

## Table of Contents
1. [Quick Startup Guide](#1-quick-startup-guide)
2. [Configuration Guide & Environment Variables](#2-configuration-guide--environment-variables)
3. [How to Use the Application](#3-how-to-use-the-application)
4. [Wazuh SIEM Integration Guide](#4-wazuh-siem-integration-guide)
5. [Threat Intelligence & Telegram Setup](#5-threat-intelligence--telegram-setup)
6. [PGlite Browser-WASM & SQL Console](#6-pglite-browser-wasm--sql-console)
7. [Troubleshooting & Common Workarounds](#7-troubleshooting--common-workarounds)

---

## 1. Quick Startup Guide

The platform consists of two services:
1. **Golang Core Engine** (Runs on port `8080`)
2. **Next.js Operations Dashboard** (Runs on port `3000`)

### Option A: Running on Windows (PowerShell)

#### Terminal 1 — Start the Backend:
```powershell
cd D:\SIEM\backend
.\server.exe
```
*(If you want to run from Go source: `go run cmd/server/main.go`)*

#### Terminal 2 — Start the Frontend:
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

Create or update `backend/.env` with your settings:

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

> **Smart Fallback Feature**: If you don't provide CTI API keys yet, the backend automatically provides deterministic threat simulation for test IOCs (e.g., `118.25.6.39`, `198.51.100.42`), so the entire system works out of the box with zero external dependencies.

---

### 2.2 Core Scoring & Asset Rules (`backend/config/config.yaml`)

Edit `backend/config/config.yaml` to adjust threat calculation behavior:

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

By default, the dashboard connects to `http://localhost:8080` and `ws://localhost:8080/ws/alerts`. If running on remote hosts or behind a domain:

```env
NEXT_PUBLIC_API_URL=http://your-server-ip:8080/api/v1
NEXT_PUBLIC_WS_URL=ws://your-server-ip:8080/ws/alerts
```

---

## 3. How to Use the Application

### 3.1 Live Operations Dashboard
1. Open **[http://localhost:3000](http://localhost:3000)**.
2. In the top navigation bar, check the status badges:
   - **Go Core WS: CONNECTED** (green pulsating dot).
   - **PGlite WASM Active** (indicates browser PostgreSQL database is online).
3. The summary cards show **Total Ingested**, **Critical Threats**, **High Severity**, **Contained / Triaged**, and **Average Risk Score**.

### 3.2 Simulating Threat Scenarios
Click the **"Simulate Attack"** button in the top right to instantly generate realistic security events:
- **Cobalt Strike C2 Beacon**: Flagged external IP targeting a Domain Controller (triggers automated containment).
- **Ransomware Shadow Deletion**: `vssadmin.exe` execution with malicious file hash on a production database.
- **Log4j RCE (CVE-2021-44228)**: JNDI injection payload targeting payment gateway.
- **Distributed SSH Brute Force**: Repeated failed logins from reputation-flagged IP.
- **SYN Stealth Port Scan**: Port sweep reconnaissance.

### 3.3 Performing Triage Actions
On each alert card, analysts can click:
- **🚫 Block IP**: Sends firewall edge drop instruction and marks alert `CONTAINED`.
- **🛡️ Isolate Host**: Network isolation for compromised endpoint and marks alert `CONTAINED`.
- **✅ Mark Triaged**: Verifies remediation and marks alert `TRIAGED`.
- **❌ Dismiss**: Flags false-positive and marks alert `DISMISSED`.

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

# Arguments passed by Wazuh:
# sys.argv[1]: alert file path
# sys.argv[2]: api key (if configured)
# sys.argv[3]: hook_url
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

Make the script executable:
```bash
chmod 750 /var/ossec/integrations/custom-soar
chown root:wazuh /var/ossec/integrations/custom-soar
systemctl restart wazuh-manager
```

---

### Step 4.3: Manual Webhook Test (Dry Run)

You can test the ingestion endpoint anytime using PowerShell or cURL:

#### PowerShell:
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/v1/alerts/ingest" `
  -Method Post `
  -ContentType "application/json" `
  -Body '{
    "source": "Wazuh-SIEM",
    "rule_id": "100201",
    "description": "Suspicious External Connection Detected",
    "severity": "HIGH",
    "indicators": {
      "ip": "118.25.6.39",
      "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }'
```

#### cURL (Linux/macOS):
```bash
curl -X POST http://localhost:8080/api/v1/alerts/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "Wazuh-SIEM",
    "event_type": "Cobalt Strike C2 Beaconing Detected",
    "severity": "CRITICAL",
    "src_ip": "118.25.6.39",
    "domain": "telemetry-update-services.org",
    "asset_id": "dc-01.domain.corp"
  }'
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
2. Create a channel or group, add your bot, and obtain your **Chat ID** (e.g., via `@userinfobot` or messaging the bot and checking `https://api.telegram.org/bot<TOKEN>/getUpdates`).
3. Add `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` to `backend/.env`.
4. Alerts with score $\ge 60$ will dispatch inline cards with clickable triage buttons.

---

## 6. PGlite Browser-WASM & SQL Console

### 6.1 What is PGlite?
PGlite is a full **PostgreSQL engine compiled to WebAssembly (WASM)** that runs entirely inside the analyst's browser.
- **Storage**: Persists data inside `idb://soc-alerts-db` (IndexedDB) or in-memory fallback.
- **Zero Latency**: Client queries execute in < 2ms without round-trips to an external database server.
- **Offline Capable**: The database remains intact across page refreshes.

### 6.2 Using the Built-in SQL Console
Click the **"SQL Console"** button in the dashboard header to query your local database.

#### Useful SQL Queries to Run:
```sql
-- View top critical threats
SELECT alert_uuid, source, event_type, calculated_score, status 
FROM alerts 
ORDER BY calculated_score DESC;

-- View indicators joined with alert scores
SELECT a.alert_uuid, a.source, i.ioc_type, i.ioc_value, a.calculated_score 
FROM alerts a 
JOIN alert_iocs i ON a.alert_uuid = i.alert_uuid;

-- Threat intelligence provider performance summary
SELECT provider, COUNT(*) as detections, ROUND(AVG(normalized_score), 2) as avg_score 
FROM enrichment_data 
GROUP BY provider;

-- Audit trail of triage actions performed
SELECT * FROM triage_actions ORDER BY performed_at DESC;
```

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
2. If accessing the frontend from a different machine or IP, ensure `NEXT_PUBLIC_WS_URL=ws://<BACKEND_IP>:8080/ws/alerts` is set in `frontend/.env.local` and restart `npm run dev`.

### Issue 3: PGlite Falls Back to In-Memory Mode
**Workaround**:
If your browser runs in strict private/incognito mode, `IndexedDB` might be disabled by browser policy. PGlite automatically handles this by switching to in-memory WASM mode. To enable persistence, use a standard browser window with IndexedDB permitted.

### Issue 4: External CTI API Rate Limits
**Workaround**:
Free CTI tiers typically allow limited queries (e.g., VirusTotal 4 req/min). If an external query fails or times out, the platform catches the error gracefully, returns `0` score for that specific provider without failing the pipeline, and processes the remaining providers within the 2500ms context deadline.
