# Automated SOC Alert Enrichment & Triage Platform (PGlite WASM Edition)

Enterprise-grade SIEM/SOAR middleware designed to ingest high-volume security telemetry, execute asynchronous multi-threat intelligence enrichment, calculate deterministic risk scores, and present actionable alerts to Security Operations Center (SOC) analysts in real time with a browser-native PostgreSQL WebAssembly engine.

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
|  |  React Dark Mode SOC Dashboard   |  |
|  +-----------------------------------+  |
+-----------------------------------------+
```

---

## 2. Key Features

- **Sub-Second Ingestion**: Golang Gin engine returns `HTTP 202 Accepted` in < 15ms by pushing tasks into bounded internal channels (`chan ProcessingTask`).
- **Concurrent Goroutine Fan-Out**: Threat intelligence queries to VirusTotal, AbuseIPDB, and Shodan execute simultaneously with a 2500ms context deadline.
- **Deterministic Composite Threat Scoring**:
  $$S_{comp} = \min\left(100, \sum (W_i \cdot S_i) \times M_{asset}\right)$$
  - VirusTotal Weight: `0.40`
  - AbuseIPDB Weight: `0.35`
  - Shodan Weight: `0.25`
  - Critical asset multiplier: `1.0 - 1.5`
- **PGlite (PostgreSQL in WebAssembly)**: Runs a complete PostgreSQL relational database engine natively in the analyst's browser. Persists alerts and triage audits in `idb://soc-alerts-db` (IndexedDB) with zero server-side database dependencies.
- **Built-in Browser SQL Console**: Analysts can run direct PostgreSQL queries (`SELECT`, `JOIN`, `GROUP BY`) against live telemetry in browser memory with sub-millisecond query latency.
- **Bi-Directional Telegram Triage**: Alerts scoring $\ge 60$ trigger Telegram alert cards with interactive buttons (`🚫 Block IP`, `🛡️ Isolate Host`, `❌ Ignore Alert`), updating the dashboard in real time.
- **Attack Simulation Suite**: One-click scenario injector (Cobalt Strike C2, Ransomware VSS Deletion, Log4j RCE, SSH Brute Force, Port Scan).

---

## 3. Project Structure

```
SIEM/
├── backend/                        # Golang Service
│   ├── cmd/server/main.go          # Application entry point
│   ├── config/config.yaml          # Scoring rules, weights & API configuration
│   ├── internal/
│   │   ├── api/
│   │   │   ├── http/handler.go     # Ingestion & Triage REST endpoints
│   │   │   └── websocket/hub.go    # Real-time WebSocket broadcasting hub
│   │   ├── cti/                    # Threat Intel Services
│   │   │   ├── types.go            # CTI interfaces & models
│   │   │   ├── virustotal.go       # VirusTotal v3 client
│   │   │   ├── abuseipdb.go        # AbuseIPDB v2 client
│   │   │   └── shodan.go           # Shodan REST client
│   │   ├── engine/
│   │   │   ├── types.go            # Pipeline data types
│   │   │   ├── enricher.go         # Goroutine fan-out orchestrator
│   │   │   ├── scorer.go           # Composite risk calculation engine
│   │   │   └── scorer_test.go      # Scorer unit tests
│   │   └── notifier/
│   │       └── telegram.go         # Telegram bot notifications & callbacks
│   ├── Dockerfile
│   ├── go.mod
│   └── go.sum
│
├── frontend/                       # Next.js Operations UI
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx            # Live SOC Alert Board Dashboard
│   │   │   ├── layout.tsx          # Root Layout & dark theme
│   │   │   └── globals.css         # Tailwind & custom scrollbars
│   │   ├── components/
│   │   │   ├── AlertCard.tsx       # Alert Card & Remediation Controls
│   │   │   ├── ThreatChart.tsx     # Recharts analytics visualizations
│   │   │   ├── SqlConsole.tsx      # Browser-native PGlite SQL Query Console
│   │   │   └── SimulationModal.tsx # Telemetry attack scenario generator
│   │   ├── lib/
│   │   │   ├── pglite.ts           # PGlite WASM client DB & DDL schema
│   │   │   └── websocket.ts        # Real-time WebSocket listener hook
│   │   └── types/
│   │       └── alert.ts            # TypeScript definitions
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
# Run server (default port: 8080)
go run cmd/server/main.go
# Or execute pre-compiled binary:
./server.exe
```

### Step 2: Run Next.js Frontend Console
```bash
cd frontend
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

The Go engine enriches the IOCs in parallel, computes the threat score, pushes the event via WebSockets to the Next.js frontend, and stores it in your browser's local **PGlite PostgreSQL database**.

---

## 6. Docker Deployment

To launch the full stack with Docker Compose:
```bash
cd deployments
docker-compose up --build
```
