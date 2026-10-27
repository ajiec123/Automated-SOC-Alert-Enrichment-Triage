# Automated SOC Alert Enrichment & Triage Platform
## Technical Architecture Specification & Implementation Blueprint (PGlite WASM Edition)

---

# 1. System Overview

The **Automated SOC Alert Enrichment & Triage Platform** is an enterprise-grade SIEM/SOAR middleware designed to ingest high-volume security telemetry, execute asynchronous multi-threat intelligence enrichment, calculate deterministic risk scores, and present actionable alerts to Security Operations Center (SOC) analysts in real time.

This architecture leverages **PGlite (PostgreSQL compiled to WebAssembly)** running natively inside the browser via IndexedDB/OPFS for ultra-fast, zero-latency local database operations, while the **Golang Backend Core** handles high-throughput ingestion, parallel API enrichment, and WebSocket streaming.

## 1.1 Core Objectives
- **Sub-Second Ingestion:** High-concurrency HTTP/Webhook ingestion using Golang to process incoming alerts without dropped frames.
- **Asynchronous Fan-Out Enrichment:** Goroutine-based orchestration to query external threat intelligence APIs (VirusTotal, AbuseIPDB, Shodan) concurrently.
- **Deterministic Risk Scoring:** Dynamic weighted algorithmic evaluation of Indicators of Compromise (IOCs) combined with asset criticalities.
- **Browser-Native SQL Engine (PGlite):** Full PostgreSQL database running in WebAssembly directly inside the analyst's browser for instant client-side querying and offline persistence via IndexedDB.
- **Bi-Directional Triage Workflow:** Real-time WebSockets stream to the frontend dashboard and instant containment actions via interactive Telegram Bot callbacks.
- **Zero-Trust Remote Access:** Secure ingress and egress architecture leveraging Cloudflare Tunnels and Tailscale Mesh Networks to eliminate open inbound firewall ports.

---

# 2. System Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                                 ALERT SOURCES                                     |
|                        (Wazuh SIEM / EDR / External Webhooks)                     |
+--------------------------+---------------------------+----------------------------+
                           |                           |
                           +-------------+-------------+
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
|  |                                                                             |  |
|  |   +-------------------+  +-------------------+  +-------------------+      |  |
|  |   | VirusTotal API    |  |  AbuseIPDB API    |  |    Shodan API     |      |  |
|  |   +---------+---------+  +---------+---------+  +---------+---------+      |  |
|  |             |                      |                      |                |  |
|  |             +----------------------+----------------------+                |  |
|  |                                    | Fan-In (sync.WaitGroup)               |  |
|  |                                    v                                       |  |
|  +------------------------------------+----------------------------------------+  |
|                                       |                                           |
|                                       v                                           |
|  +-----------------------------------------------------------------------------+  |
|  | Risk Engine & Normalizer (Scoring Thresholds & Asset Matrix)               |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
+----------------------------------------+------------------------------------------+
                                         |
            +----------------------------+----------------------------+
            |                                                         |
            v (WebSocket Stream / Event Push)                         v (Inline Cards)
+-----------------------------------------+         +-------------------------------+
|       CLIENT BROWSER (NEXT.JS)          |         |     NOTIFICATION & TRIAGE     |
|                                         |         |     [ Telegram Bot API ]      |
|  +-----------------------------------+  |         |     - Rich Card Alerts        |
|  |  PGlite (Postgres WASM Engine)    |  |         |     - Inline Callbacks        |
|  |  - Full SQL Execution in Memory   |  |         +-------------------------------+
|  |  - Persistence via IndexedDB/OPFS |  |
|  +-----------------------------------+  |
|  |  React Operations Dashboard UI    |  |
|  +-----------------------------------+  |
+-----------------------------------------+
```

---

# 3. Ingestion & Webhook Pipeline

## 3.1 Webhook Lifecycle
1. **Ingress Validation:** Incoming payload header validation via HTTP Basic Auth or HMAC SHA-256 signature verification.
2. **Payload Parsing:** JSON decoder parses incoming raw alerts into standardized schema representations.
3. **Queue Hand-Off:** Ingested payloads are pushed into a buffered internal channel (`chan ProcessingTask`) returning `HTTP 202 Accepted` to the upstream SIEM/EDR source within < 15ms.

## 3.2 Webhook Ingestion Data Structure
```go
type AlertPayload struct {
    ID          string                 `json:"alert_id"`
    Source      string                 `json:"source"`
    EventType   string                 `json:"event_type"`
    Timestamp   time.Time              `json:"timestamp"`
    Severity    string                 `json:"severity"`
    SrcIP       string                 `json:"src_ip,omitempty"`
    DstIP       string                 `json:"dst_ip,omitempty"`
    FileHash    string                 `json:"file_hash,omitempty"`
    Domain      string                 `json:"domain,omitempty"`
    RawMetadata map[string]interface{} `json:"metadata"`
}
```

---

# 4. Enrichment Engine & Goroutine Concurrency

The Go engine uses concurrency primitives (`goroutines`, `channels`, `sync.WaitGroup`, and `context.WithTimeout`) to query all Threat Intelligence (CTI) providers simultaneously.

```
                  [ Ingest Payload Normalized ]
                              |
             +----------------+----------------+
             | Fan-Out (Goroutines)            |
             v                                 v
   [ Goroutine: VirusTotal ]       [ Goroutine: AbuseIPDB ]
             |                                 |
             +----------------+----------------+
                              | Fan-In (Context Deadline: 2500ms)
                              v
                   [ Aggregate & Score Risk ]
```

## 4.1 Orchestrator Implementation Pattern
```go
package enrichment

import (
    "context"
    "sync"
    "time"
)

type CTIResult struct {
    Provider string
    Score    float64
    Details  map[string]interface{}
    Error    error
}

func EnrichIOC(parentCtx context.Context, ioc string, iocType string) []CTIResult {
    ctx, cancel := context.WithTimeout(parentCtx, 2500*time.Millisecond)
    defer cancel()

    providers := []CTIProvider{VirusTotalProvider{}, AbuseIPDBProvider{}, ShodanProvider{}}
    resultsChan := make(chan CTIResult, len(providers))
    var wg sync.WaitGroup

    for _, provider := range providers {
        wg.Add(1)
        go func(p CTIProvider) {
            defer wg.Done()
            res, err := p.Query(ctx, ioc, iocType)
            if err != nil {
                resultsChan <- CTIResult{Provider: p.Name(), Error: err}
                return
            }
            resultsChan <- res
        }(provider)
    }

    wg.Wait()
    close(resultsChan)

    var aggregated []CTIResult
    for res := range resultsChan {
        aggregated = append(aggregated, res)
    }
    return aggregated
}
```

---

# 5. Threat Scoring Logic & Action Thresholds

The system calculates a dynamic Composite Threat Score ($S_{comp}$) scaled from $0$ to $100$.

## 5.1 Scoring Formula
$$S_{comp} = \min\left(100, \sum_{i=1}^{n} (W_i \cdot S_i) \times M_{asset}\right)$$

Where:
- $W_i$ = Provider Weight factor ($\sum W_i = 1.0$)
- $S_i$ = Provider Threat Score Normalized ($0 - 100$)
- $M_{asset}$ = Asset Criticality Multiplier ($0.8$ to $1.5$)

## 5.2 Provider Weights
| Provider | Weight ($W_i$) | Normalization Mapping |
| :--- | :--- | :--- |
| **VirusTotal** | 0.40 | Malicious Detections Ratio $\times 100$ |
| **AbuseIPDB** | 0.35 | Confidence Score ($0-100\%$) |
| **Shodan** | 0.25 | Vulnerability & Open Port Risk Scale ($0-100$) |

## 5.3 Severity Tiers
| Composite Score Range | Severity Level | Automated Action Workflow |
| :--- | :--- | :--- |
| **80 – 100** | **CRITICAL** | Auto-block firewall rule, immediate Telegram alert, WebSocket push to PGlite. |
| **60 – 79** | **HIGH** | Immediate Telegram alert with interactive inline containment options. |
| **30 – 59** | **MEDIUM** | Ingest to PGlite, update SOC dashboard stream, mark for analyst review. |
| **0 – 29** | **LOW / INFORMATIONAL** | Low priority client-side storage, aggregate report metrics only. |

---

# 6. PGlite (Browser-WASM PostgreSQL) Schema Design

PGlite executes full PostgreSQL DDL inside the browser runtime, persisting state through `IndexedDB` (`idb://soc-alerts-db`) or `OPFS`.

```sql
-- DDLExecuted inside PGlite (Browser Context)

CREATE TYPE alert_status AS ENUM ('NEW', 'ENRICHED', 'TRIAGED', 'CONTAINED', 'DISMISSED');

-- Alerts Master Table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_uuid UUID NOT NULL UNIQUE,
    source VARCHAR(64) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    severity_raw VARCHAR(32) NOT NULL,
    calculated_score NUMERIC(5,2) DEFAULT 0.00,
    status alert_status DEFAULT 'NEW',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indicators of Compromise (IOCs)
CREATE TABLE IF NOT EXISTS alert_iocs (
    id SERIAL PRIMARY KEY,
    alert_uuid UUID REFERENCES alerts(alert_uuid) ON DELETE CASCADE,
    ioc_type VARCHAR(32) NOT NULL,
    ioc_value TEXT NOT NULL
);

-- Enrichment Details Table (JSONB Supported natively by PGlite)
CREATE TABLE IF NOT EXISTS enrichment_data (
    id SERIAL PRIMARY KEY,
    alert_uuid UUID REFERENCES alerts(alert_uuid) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    raw_response JSONB NOT NULL,
    normalized_score NUMERIC(5,2) NOT NULL,
    fetched_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Triage Audit Logs
CREATE TABLE IF NOT EXISTS triage_actions (
    id SERIAL PRIMARY KEY,
    alert_uuid UUID REFERENCES alerts(alert_uuid) ON DELETE CASCADE,
    actor VARCHAR(128) NOT NULL,
    action_taken VARCHAR(64) NOT NULL,
    notes TEXT,
    performed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Client-Side Indexes for Rapid SQL Filtering
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(calculated_score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
```

---

# 7. Real-Time Telegram Integration

## 7.1 Telegram Card Layout
When an alert score exceeds $\ge 60$, the system dispatches a rich Telegram MarkdownV2 message containing metadata and inline action buttons:

```
+-------------------------------------------------------------+
| 🚨 [CRITICAL ALERT] - High Threat Score Detected            |
+-------------------------------------------------------------+
| ID:         ALT-890241                                      |
| Score:      88.5 / 100                                      |
| Source:     Wazuh SIEM                                      |
| Indicator:  198.51.100.42 (IP)                              |
| Enrichment: VirusTotal (14/70) | AbuseIPDB (92%)            |
+-------------------------------------------------------------+
| [ 🚫 Block IP ]   [ 🛡️ Isolate Host ]   [ ❌ Ignore Alert ] |
+-------------------------------------------------------------+
```

## 7.2 Interactive Telegram Execution Flow
1. Analyst taps **[ 🚫 Block IP ]** in Telegram.
2. Telegram sends a POST request containing `callback_query` to Go API `/api/v1/telegram/callback`.
3. Go backend processes the action, logs the triage, and broadcasts a WebSocket event to update PGlite in the Web UI.

---

# 8. Zero-Trust Network & Remote Access Setup

## 8.1 Cloudflare Tunnel Configuration (`cloudflared`)
```yaml
# /etc/cloudflared/config.yml
tunnel: 9a8b7c6d-5e4f-3a2b-1c0d-fe9876543210
credentials-file: /etc/cloudflared/9a8b7c6d-5e4f-3a2b-1c0d-fe9876543210.json
ingress:
  - hostname: soar-ingest.company-soc.internal
    service: http://localhost:8080
    originRequest:
      connectTimeout: 5s
      noTLSVerify: false
  - service: http_status:404
```

## 8.2 Tailscale Zero-Trust Node Setup
```bash
# Register SOC Workstation inside private Tailnet
sudo tailscale up --authkey=tskey-auth-k1234567890-abcdef123456789 \
  --advertise-tags=tag:soc-platform \
  --accept-routes
```

---

# 9. Project Folder Structure

```
soc-enrichment-platform/
├── backend/                        # Golang Service
│   ├── cmd/
│   │   └── server/
│   │       └── main.go             # Go application entry point
│   ├── config/
│   │   └── config.yaml             # Core API keys & scoring rules
│   ├── internal/
│   │   ├── api/
│   │   │   ├── http/               # Webhook Ingestion Handlers
│   │   │   └── websocket/          # Push alerts stream to Next.js
│   │   ├── cti/                    # Threat Intel Services
│   │   │   ├── virustotal.go       # VT Client
│   │   │   ├── abuseipdb.go        # AbuseIPDB Client
│   │   │   └── shodan.go           # Shodan Client
│   │   ├── engine/
│   │   │   ├── enricher.go         # Goroutine Orchestrator
│   │   │   └── scorer.go           # Risk Score Engine
│   │   └── notifier/
│   │       └── telegram.go         # Bot Callbacks & Messaging
│   ├── go.mod
│   └── go.sum
│
├── frontend/                       # Next.js Operations UI
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx            # Live Alert Board Dashboard
│   │   │   └── layout.tsx          # Root Layout
│   │   ├── components/
│   │   │   ├── AlertCard.tsx       # Alert Item Component
│   │   │   └── ThreatChart.tsx     # Recharts Analytics Component
│   │   ├── lib/
│   │   │   ├── pglite.ts           # PGlite Browser Database Setup
│   │   │   └── websocket.ts        # Live Stream Socket Hook
│   │   └── types/
│   │       └── alert.ts            # TypeScript Models
│   ├── package.json
│   └── tailwind.config.js
│
├── deployments/
│   ├── cloudflared/
│   │   └── config.yml              # Tunnel configuration
│   └── docker-compose.yml          # Containerized local runner
└── README.md
```