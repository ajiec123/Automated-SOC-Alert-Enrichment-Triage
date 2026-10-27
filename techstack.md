# Automated SOC Alert Enrichment & Triage Platform

## Technical Stack Specification & System Topology (PGlite WASM Edition)

The Automated Security Operations Center (SOC) Alert Enrichment & Triage Platform bridges Security Information and Event Management (SIEM) ingest pipelines with Security Orchestration, Automation, and Response (SOAR) capabilities. The architecture is engineered for low-latency ingestion, asynchronous Threat Intelligence (TI) enrichment, dynamic alert scoring, real-time WebSockets streaming, and client-side PostgreSQL database execution via PGlite WASM.

```
                  +-------------------------------------------------+
                  |         Security Data Ingestion / SIEM          |
                  +-------------------------------------------------+
                                           |
                                           v
                  +-------------------------------------------------+
                  |          Golang High-Throughput Core            |
                  |  - REST Ingestion Engine (Fiber/Gin API)        |
                  |  - Goroutine Async Enrichment & Scoring Engine  |
                  +-------------------------------------------------+
                      /                    |                    \
                     /                     |                     \
                    v                      v                      v
        +-----------------------+ +------------------+ +-----------------------+
        | External TI Providers | | Real-Time Push   | | Analyst Interfaces    |
        | - VirusTotal API v3   | | - WebSockets Feed| | - Next.js Operations  |
        | - AbuseIPDB API v2    | |   to Front-end   | |   Dashboard           |
        | - Shodan REST API     | +------------------+ | - PGlite (Postgres    |
        +-----------------------+                      |   WASM in Browser)    |
                                                       | - Telegram Bot Remote |
                                                       +-----------------------+
```

---

# 1. Backend Stack Architecture

The backend application layer is written in **Golang**, chosen for its concurrent processing capabilities, minimal memory footprint, and low-latency execution under high ingestion loads.

## Core Backend Components

| Component | Framework / Library | Primary Responsibility |
| ----- | ----- | ----- |
| **HTTP Web Engine** | Fiber (or Gin) | Provides high-performance RESTful APIs for webhook ingestion, alert query routing, and administrative endpoints. |
| **Real-time Pipeline** | Gorilla WebSocket / Fiber WebSocket | Pushes live enriched alerts and system telemetry events directly to operational dashboards in the browser. |
| **Asynchronous Job Worker** | Native Worker Pools (Goroutines + Channels) | Handles non-blocking execution of external API enrichment requests (VirusTotal, AbuseIPDB, Shodan) and alert evaluation logic. |
| **Notification Engine** | `go-telegram-bot-api` | Dispatches high-severity alerts to Telegram channels and processes interactive callback queries (e.g., Containment / Mitigation actions). |

---

# 2. Frontend Operations Dashboard & Local Database (PGlite WASM)

The frontend operational console delivers real-time visibility into incoming alert telemetry, risk scores, enriched IOC indicators, and manual response trigger overrides.

## Core Frontend Components

| Layer | Technology | Functionality |
| ----- | ----- | ----- |
| **Application Framework** | Next.js (App Router) | React-based UI framework providing SSR for dashboard layouts and App Router structure. |
| **Embedded Client DB** | **PGlite (`@electric-sql/pglite`)** | Full PostgreSQL engine compiled to WebAssembly running directly inside the analyst's browser. Handles zero-latency client-side SQL querying and data persistence via IndexedDB / OPFS. |
| **Styling Engine** | Tailwind CSS | Utility-first, standardized design system supporting high-density dark mode UI layouts suitable for SOC environments. |
| **Iconography** | Lucide Icons | Visual cues for threat severity levels, network indicators, asset categories, and action state indicators. |
| **Data Visualization** | Recharts | Interactive visualization of alert velocity trends, threat classification distributions, and enrichment latency metrics. |

---

# 3. Database Architecture & Client Storage Model

## Client-Side Persistent Engine: PGlite (Postgres WASM)

Instead of relying on an external database server for dashboard views, the browser runs PostgreSQL natively using PGlite.

* **Storage Target:** `IndexedDB` (`idb://soc-alerts-db`) or `OPFS` (Origin Private File System).
* **Time-to-Live (TTL):** Default 24-hour cache invalidation window managed client-side for volatile threat intelligence payloads.
* **Query Performance:** Sub-millisecond SQL queries executed directly in browser memory without server network round-trips.

---

# 4. Threat Intelligence Integrations

The system enriches incoming indicators through an automated, parallel lookup queue across multiple Threat Intelligence providers via Golang Goroutines.

| Provider | Endpoint Standard | Target Indicator Types | Critical Enriched Attributes |
| ----- | ----- | ----- | ----- |
| **VirusTotal API v3** | REST API v3 (`/api/v3/`) | File Hashes, IP Addresses, Domains, URLs | Malicious analysis engine consensus count, community threat category flags, reputation score. |
| **AbuseIPDB API v2** | REST API v2 (`/api/v2/check`) | IPv4, IPv6 Addresses | Abuse confidence score, total report count, last reported timestamp, country code, ISP domain. |
| **Shodan REST API** | REST API (`/shodan/host/`) | Public IP Addresses | Open network ports, active service banners, known vulnerabilities (CVEs), organizational ownership. |

---

# 5. Remote Access & Telegram Bot Operations

## Telegram Bot Integration

* **Alert Notifications:** Instant messaging delivery for critical severity alerts containing threat summaries, IOC breakdowns, and inline triage action buttons.
* **Remote Triage Commands:** Analysts can acknowledge, isolate host, close, or escalate alerts directly from Telegram via secure callback queries.

## Zero-Trust Infrastructure Access Control

* **Cloudflare Tunnels (`cloudflared`):** Exposes the Next.js Operations Dashboard and Ingestion Webhooks securely to the internet without opening inbound firewall ports.
* **Tailscale Integration:** Establishes a private WireGuard-based overlay network for direct admin access to SSH, backend debug logs, and internal configuration setups.

---

# 6. Environment Configuration (`.env` Template)

```env
# SERVER CONFIGURATION
PORT=8080
ENV=production
LOG_LEVEL=info
ALLOWED_ORIGINS=https://soc.company.internal

# THREAT INTEL API KEYS
VIRUSTOTAL_API_KEY=your_virustotal_api_v3_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_v2_key
SHODAN_API_KEY=your_shodan_rest_api_key

# TELEGRAM BOT INTEGRATION
TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
TELEGRAM_CHAT_ID=-1001234567890

# SECURITY & ZERO TRUST
CF_TUNNEL_TOKEN=your_cloudflare_tunnel_token
TAILSCALE_AUTH_KEY=tskey-auth-xxxxxx-xxxxxx
```

---

# 7. Developer Setup & Deployment Guide

## Prerequisites

* **Go** (v1.22+)
* **Node.js** (v18.x / v20.x LTS) & **npm / pnpm**
* **Git**

## Step 1: Backend Service Setup (Golang Core Engine)

```bash
cd backend
# Populate .env file
go mod download
go run cmd/server/main.go
```

## Step 2: Frontend Dashboard Setup (Next.js + PGlite)

```bash
cd frontend
npm install @electric-sql/pglite lucide-react recharts
npm run dev
```

## Step 3: Verification & Ingestion Dry-Run Test

```bash
curl -X POST http://localhost:8080/api/v1/alerts/ingest \
  -H "Content-Type: application/json" \
  -d '{
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