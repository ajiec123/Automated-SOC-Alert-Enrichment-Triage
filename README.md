# Automated SOC Alert Enrichment & Triage Platform (PGlite WASM Edition)

Enterprise-grade SIEM/SOAR middleware and modern operations console designed to ingest high-volume security telemetry, execute asynchronous multi-threat intelligence enrichment, calculate deterministic risk scores, and present actionable alerts to Security Operations Center (SOC) analysts in real time with a browser-native PostgreSQL WebAssembly engine.

---

## 1. System Topology & Architecture

```
+-----------------------------------------------------------------------------------+
|                                 ALERT SOURCES                                     |
|                        (Wazuh SIEM / EDR / External Webhooks)                     |
+--------------------------+---------------------------+----------------------------+
                           | HTTP Webhooks (TLS 1.3)
                           v
+-----------------------------------------------------------------------------------+
|                        INGRESS & ZERO-TRUST LAYER                                 |
|  [ Cloudflare Tunnel / Edge ] <---> [ Access Control / HMAC Signature Verify ]    |
+----------------------------------------+------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        GO CORE ENGINE (SOAR MIDDLEWARE)                           |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Ingestion Worker Pool (Worker Queues & Bounded Buffers)                      |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  | Asynchronous Threat Intelligence Orchestrator (Goroutine Fan-Out)           |  |
|  |   - VirusTotal API v3 (Weight: 0.40)                                        |  |
|  |   - AbuseIPDB API v2  (Weight: 0.35)                                        |  |
|  |   - Shodan REST API   (Weight: 0.25)                                        |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  | Risk Engine & Normalizer (Composite Scoring: 0 - 100 with Asset Multipliers)|  |
|  +-------------------------------------+---------------------------------------+  |
+----------------------------------------+------------------------------------------+
                                         |
            +----------------------------+----------------------------+
            |                                                         |
            v (WebSocket Stream: ws://localhost:8080/ws/alerts)       v (Rich Inline Cards)
+-----------------------------------------+         +-------------------------------+
|       CLIENT BROWSER (NEXT.JS)          |         |     NOTIFICATION & TRIAGE     |
|                                         |         |     [ Telegram Bot API ]      |
|  +-----------------------------------+  |         |     - Rich Card Alerts        |
|  |  PGlite (Postgres WASM Engine)    |  |         |     - Inline Action Callbacks |
|  |  - Full SQL Execution in Browser  |  |         +-------------------------------+
|  |  - IndexedDB Persistence (idb://) |  |
|  +-----------------------------------+  |
|  |  React Dark/Light SOC Dashboard   |  |
|  |  - MITRE ATT&CK Matrix Heatmap    |  |
|  |  - Attack Storylines & Graph View |  |
|  |  - Root Cause & Hypothesis Triage |  |
|  |  - Automated SOAR Playbook Engine |  |
|  |  - Interactive IOC Flyout Drawer  |  |
|  |  - One-Click Handover Report (.MD)|  |
|  +-----------------------------------+  |
+-----------------------------------------+
```

---

## 2. Key Features

### 🚀 Core Engineering & Pipeline
- **Sub-Second Ingestion**: Golang Gin engine returns `HTTP 202 Accepted` in < 15ms by pushing tasks into bounded internal channels (`chan ProcessingTask`).
- **Concurrent Goroutine Fan-Out**: Simultaneous queries to VirusTotal, AbuseIPDB, and Shodan with a 2500ms context deadline.
- **Deterministic Composite Threat Scoring**:
  $$S_{comp} = \min\left(100, \sum (W_i \cdot S_i) \times M_{asset}\right)$$
  - VirusTotal: `0.40` | AbuseIPDB: `0.35` | Shodan: `0.25`
  - Critical asset multiplier: `1.0 - 1.5`
- **PGlite (PostgreSQL in WebAssembly)**: Runs a complete relational PostgreSQL engine natively in the analyst's browser. Persists alerts and triage audits in `idb://soc-alerts-db` (IndexedDB) with memory fallback and zero server database requirements.
- **Bi-Directional Telegram Triage**: Alerts scoring $\ge 60$ dispatch rich interactive cards to Telegram with inline buttons (`🚫 Block IP`, `🛡️ Isolate Host`, `❌ Dismiss`).

### 🛡️ Advanced SOC Analyst Capabilities (Next-Level Updates)
- **Structured Root Cause & Hypothesis Verdicts**:
  - Structured **CAUSE**, **OTHER HYPOTHESES, STILL OPEN / CONFIRMED / REFUTED** with supporting and contradicting evidence, **WHAT WOULD SETTLE IT** (verification tests), and **WHAT TO DO** recommendations.
  - Analysts link their remediation verdicts (`Block IP`, `Isolate Host`, `Mark Triaged`, `Dismiss`) directly to a specific hypothesis target.
- **MITRE ATT&CK® Enterprise Heatmap**:
  - Live interactive matrix mapping alerts across all 13 adversary tactics (`Reconnaissance` → `Initial Access` → `Command and Control` → `Impact`).
- **Correlated Multi-Stage Attack Storylines & Graph View**:
  - Correlates isolated alerts by attacker IP infrastructure or targeted asset into unified **Incidents (`INC-XXXXXX`)**.
  - Includes a visual **Lateral Movement Attack Graph** showing sequential adversary pivots (`Stage 1 → PIVOT → Stage 2 → Stage 3`).
- **Automated SOAR Playbook Execution Engine**:
  - Real-time animated execution drawer simulating automated containment steps (CrowdStrike EDR network severance, Palo Alto firewall edge injection, DNS sinkholing, RAM dumps, Telegram notifications).
- **Interactive IOC Threat Hunting Drawer**:
  - Click any IOC (IP, Hash, Domain) to open a slide-out flyout showing:
    - Geolocation & ASN telemetry.
    - Direct deep links to VirusTotal, AbuseIPDB, and Shodan.
    - One-click copyable firewall syntax (**iptables**, **Cisco ASA**, **Palo Alto**, **PowerShell**).
    - Historical cross-alert correlation in PGlite WASM.
- **One-Click Incident & Shift Handover Report Generator**:
  - Exports executive-ready TLP:AMBER briefs in **Markdown (`.md`)** and printable **PDF document layout** with KPI cards, incident tables, RCA evidence, and immutable audit trails.
- **PGlite Threat Hunting SQL Bookmarks & CSV Export**:
  - Built-in bookmarks for hunting attacker subnets, multi-CTI performance stats, and triage logs with instant **Export CSV** capability.
- **Dark & Light Mode Switching**: Seamless theme toggle with local storage persistence and hydration flash protection.

---

## 3. Project Structure

```
SIEM/
├── backend/                        # Golang Service
│   ├── cmd/server/main.go          # Application entry point & router
│   ├── config/config.yaml          # Scoring rules, weights & asset multipliers
│   ├── internal/
│   │   ├── api/
│   │   │   ├── http/handler.go     # Ingestion, simulation & triage endpoints
│   │   │   └── websocket/hub.go    # Real-time WebSocket broadcasting hub
│   │   ├── cti/                    # Threat Intelligence Clients
│   │   │   ├── types.go            # CTI interfaces & models
│   │   │   ├── virustotal.go       # VirusTotal v3 client
│   │   │   ├── abuseipdb.go        # AbuseIPDB v2 client
│   │   │   └── shodan.go           # Shodan REST client
│   │   ├── engine/
│   │   │   ├── types.go            # Pipeline models & payloads
│   │   │   ├── enricher.go         # Goroutine fan-out orchestrator
│   │   │   ├── scorer.go           # Composite risk calculation engine
│   │   │   └── scorer_test.go      # Unit tests
│   │   └── notifier/
│   │       └── telegram.go         # Telegram bot notifications & callbacks
│   ├── Dockerfile
│   ├── go.mod
│   └── go.sum
│
├── frontend/                       # Next.js 14 Operations Console
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx            # Live SOC operations console & switcher
│   │   │   ├── layout.tsx          # Root Layout & theme provider
│   │   │   └── globals.css         # Tailwind styles & theme variables
│   │   ├── components/
│   │   │   ├── AlertCard.tsx       # Root Cause & Hypothesis remediation card
│   │   │   ├── IncidentStoryline.tsx # Multi-stage correlated campaign timeline
│   │   │   ├── IncidentGraph.tsx   # Lateral movement attack node graph
│   │   │   ├── MitreHeatmap.tsx    # MITRE ATT&CK enterprise kill-chain matrix
│   │   │   ├── IOCDrawer.tsx       # Deep IOC intelligence & firewall generator
│   │   │   ├── PlaybookDrawer.tsx  # Animated SOAR playbook containment runner
│   │   │   ├── ReportModal.tsx     # One-click shift handover report generator
│   │   │   ├── SqlConsole.tsx      # PGlite WASM SQL console & CSV exporter
│   │   │   ├── SimulationModal.tsx # Telemetry attack scenario injector
│   │   │   ├── ThreatChart.tsx     # Threat distribution charts (Recharts)
│   │   │   └── ThemeToggle.tsx     # Dark/light theme toggle
│   │   ├── lib/
│   │   │   ├── pglite.ts           # PGlite client DB, schema & queries
│   │   │   ├── hypothesis.ts       # Root Cause Analysis generator
│   │   │   ├── mitre.ts            # MITRE correlation & grouping engine
│   │   │   ├── report.ts           # Executive report compiler
│   │   │   ├── theme.tsx           # Theme context & persistence
│   │   │   └── websocket.ts        # WebSocket listener with backoff & jitter
│   │   └── types/
│   │       └── alert.ts            # Complete TypeScript domain definitions
│   ├── Dockerfile
│   ├── package.json
│   └── tailwind.config.js
│
├── deployments/
│   ├── cloudflared/
│   │   └── config.yml              # Cloudflare Zero-Trust Tunnel configuration
│   └── docker-compose.yml          # Containerized local runner
├── architecture.md
├── techstack.md
├── WORKAROUND.md                   # Operational & Troubleshooting Guide
└── README.md
```

---

## 4. Quickstart Guide

### Prerequisites
- **Go** (v1.22+)
- **Node.js** (v18+) & **npm**

### Step 1: Run Backend Engine
```bash
cd backend
go run cmd/server/main.go
# Or execute pre-compiled binary:
./server.exe
```

### Step 2: Run Next.js Frontend Console
```bash
cd frontend
npm install
npm run dev
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

## 5. Verification & Testing

### Send Test Ingestion Webhook (Wazuh SIEM format)
```bash
curl -X POST http://localhost:8080/api/v1/alerts/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "Wazuh-SIEM",
    "event_type": "Cobalt Strike Malleable C2 Beaconing Detected",
    "severity": "CRITICAL",
    "src_ip": "118.25.6.39",
    "domain": "telemetry-update-services.org",
    "asset_id": "dc-01.domain.corp",
    "metadata": {
      "process": "rundll32.exe",
      "command_line": "rundll32.exe C:\\Windows\\Temp\\beacon.dll,Start"
    }
  }'
```

Response:
```json
{
  "alert_id": "ALT-890241-...",
  "message": "Alert queued for concurrent Threat Intelligence enrichment and risk calculation",
  "queue_size": 1,
  "status": "accepted"
}
```

The Go engine enriches the IOCs in parallel, computes the threat score, broadcasts the event via WebSockets to the Next.js frontend, and stores it in your browser's local **PGlite PostgreSQL database**.

---

## 6. Docker Deployment

To launch the full stack with Docker Compose:
```bash
cd deployments
docker compose up --build
```
