import { PGlite } from '@electric-sql/pglite';
import { AlertRecord, DashboardMetrics, TriageAuditLog } from '@/types/alert';

let pgliteInstance: PGlite | null = null;
let initPromise: Promise<PGlite> | null = null;

const SCHEMA_DDL = `
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_uuid VARCHAR(64) NOT NULL UNIQUE,
    source VARCHAR(64) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    severity_raw VARCHAR(32) NOT NULL,
    calculated_score NUMERIC(5,2) DEFAULT 0.00,
    status VARCHAR(32) DEFAULT 'NEW',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_iocs (
    id SERIAL PRIMARY KEY,
    alert_uuid VARCHAR(64) NOT NULL,
    ioc_type VARCHAR(32) NOT NULL,
    ioc_value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrichment_data (
    id SERIAL PRIMARY KEY,
    alert_uuid VARCHAR(64) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    raw_response JSONB NOT NULL,
    normalized_score NUMERIC(5,2) NOT NULL,
    fetched_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS triage_actions (
    id SERIAL PRIMARY KEY,
    alert_uuid VARCHAR(64) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    action_taken VARCHAR(64) NOT NULL,
    notes TEXT,
    hypothesis_selected VARCHAR(128),
    performed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(calculated_score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
`;

// Helper: wrap a promise with a timeout
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, errorMsg: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error(errorMsg)), timeoutMs)),
  ]);
}

async function createDatabaseInstance(): Promise<PGlite> {
  // First attempt: try IndexedDB persistence with a 4-second timeout
  try {
    const idbDb = new PGlite('idb://soc-alerts-db');
    await withTimeout(idbDb.waitReady, 4000, 'IndexedDB waitReady timeout');
    await withTimeout(idbDb.exec(SCHEMA_DDL), 4000, 'IndexedDB schema execution timeout');
    await seedInitialDataIfEmpty(idbDb);
    console.log('[PGlite] Successfully initialized with IndexedDB persistence (idb://soc-alerts-db)');
    return idbDb;
  } catch (idbErr) {
    console.warn('[PGlite] IndexedDB unavailable or timed out, falling back to in-memory WASM database:', idbErr);
  }

  // Second attempt: purely in-memory PGlite WASM
  try {
    const memDb = new PGlite();
    await withTimeout(memDb.waitReady, 5000, 'Memory waitReady timeout');
    await withTimeout(memDb.exec(SCHEMA_DDL), 4000, 'Memory schema execution timeout');
    await seedInitialDataIfEmpty(memDb);
    console.log('[PGlite] Successfully initialized in-memory WASM engine');
    return memDb;
  } catch (memErr) {
    console.error('[PGlite] Memory database initialization also encountered an issue:', memErr);
    throw memErr;
  }
}

export async function getPGlite(): Promise<PGlite> {
  if (typeof window === 'undefined') {
    throw new Error('PGlite WASM runs client-side inside the browser');
  }

  if (pgliteInstance) {
    return pgliteInstance;
  }

  if (!initPromise) {
    initPromise = createDatabaseInstance()
      .then((db) => {
        pgliteInstance = db;
        return db;
      })
      .catch((err) => {
        // Reset so subsequent calls can retry
        initPromise = null;
        throw err;
      });
  }

  return initPromise;
}

async function seedInitialDataIfEmpty(db: PGlite) {
  try {
    const res = await db.query<{ count: string }>('SELECT COUNT(*) as count FROM alerts;');
    const count = parseInt(res.rows[0]?.count || '0', 10);
    if (count > 0) return;

    // Seed realistic starter alerts
    const starterAlerts = [
      {
        uuid: 'ALT-890241-c2fe',
        source: 'Wazuh SIEM',
        event: 'Cobalt Strike Malleable C2 Beaconing Detected',
        rawSev: 'CRITICAL',
        score: 91.5,
        status: 'CONTAINED',
        iocs: [{ type: 'IP', val: '118.25.6.39' }, { type: 'DOMAIN', val: 'telemetry-update-services.org' }],
        cti: [
          { provider: 'VirusTotal', score: 85.0, raw: { positives: 61, total: 72 } },
          { provider: 'AbuseIPDB', score: 96.0, raw: { confidence: 96, country: 'CN' } },
          { provider: 'Shodan', score: 90.0, raw: { open_ports: [80, 443, 4444], vulns: ['CVE-2021-44228'] } },
        ]
      },
      {
        uuid: 'ALT-771920-a81d',
        source: 'Suricata NIDS',
        event: 'SSH Distributed Password Spray Attack',
        rawSev: 'HIGH',
        score: 74.2,
        status: 'ENRICHED',
        iocs: [{ type: 'IP', val: '198.51.100.42' }],
        cti: [
          { provider: 'VirusTotal', score: 62.0, raw: { positives: 44, total: 72 } },
          { provider: 'AbuseIPDB', score: 92.0, raw: { confidence: 92, country: 'RU' } },
          { provider: 'Shodan', score: 65.0, raw: { open_ports: [22, 3389], vulns: ['CVE-2019-0708'] } },
        ]
      },
      {
        uuid: 'ALT-623819-bf90',
        source: 'Zeek Bro IDS',
        event: 'Internal Lateral Kerberoasting Ticket Request',
        rawSev: 'MEDIUM',
        score: 48.0,
        status: 'NEW',
        iocs: [{ type: 'IP', val: '10.0.12.84' }],
        cti: [
          { provider: 'VirusTotal', score: 10.0, raw: { positives: 2, total: 72 } },
          { provider: 'AbuseIPDB', score: 0.0, raw: { confidence: 0, isWhitelisted: true } },
          { provider: 'Shodan', score: 20.0, raw: { open_ports: [88, 389], vulns: [] } },
        ]
      }
    ];

    for (const a of starterAlerts) {
      await db.query(
        `INSERT INTO alerts (alert_uuid, source, event_type, severity_raw, calculated_score, status)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (alert_uuid) DO NOTHING;`,
        [a.uuid, a.source, a.event, a.rawSev, a.score, a.status]
      );

      for (const ioc of a.iocs) {
        await db.query(
          `INSERT INTO alert_iocs (alert_uuid, ioc_type, ioc_value) VALUES ($1, $2, $3);`,
          [a.uuid, ioc.type, ioc.val]
        );
      }

      for (const c of a.cti) {
        await db.query(
          `INSERT INTO enrichment_data (alert_uuid, provider, raw_response, normalized_score)
           VALUES ($1, $2, $3, $4);`,
          [a.uuid, c.provider, JSON.stringify(c.raw), c.score]
        );
      }
    }
  } catch (err) {
    console.error('Failed to seed starter data into PGlite:', err);
  }
}

export async function upsertAlertInPGlite(alert: AlertRecord): Promise<void> {
  const db = await getPGlite();

  await db.query(
    `INSERT INTO alerts (alert_uuid, source, event_type, severity_raw, calculated_score, status, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
     ON CONFLICT (alert_uuid) DO UPDATE SET
       source = EXCLUDED.source,
       event_type = EXCLUDED.event_type,
       severity_raw = EXCLUDED.severity_raw,
       calculated_score = EXCLUDED.calculated_score,
       status = EXCLUDED.status,
       updated_at = CURRENT_TIMESTAMP;`,
    [
      alert.alert_uuid,
      alert.source,
      alert.event_type,
      alert.severity_raw,
      alert.calculated_score,
      alert.status || 'NEW',
    ]
  );

  if (alert.iocs && alert.iocs.length > 0) {
    // Delete existing and reinsert
    await db.query('DELETE FROM alert_iocs WHERE alert_uuid = $1;', [alert.alert_uuid]);
    for (const ioc of alert.iocs) {
      await db.query(
        'INSERT INTO alert_iocs (alert_uuid, ioc_type, ioc_value) VALUES ($1, $2, $3);',
        [alert.alert_uuid, ioc.ioc_type, ioc.ioc_value]
      );
    }
  }

  if (alert.enrichments && alert.enrichments.length > 0) {
    await db.query('DELETE FROM enrichment_data WHERE alert_uuid = $1;', [alert.alert_uuid]);
    for (const enr of alert.enrichments) {
      await db.query(
        'INSERT INTO enrichment_data (alert_uuid, provider, raw_response, normalized_score) VALUES ($1, $2, $3, $4);',
        [alert.alert_uuid, enr.provider, JSON.stringify(enr.raw_response || {}), enr.score]
      );
    }
  }
}

export async function recordTriageInPGlite(
  alertUUID: string,
  actor: string,
  action: string,
  newStatus: string,
  notes?: string,
  hypothesisSelected?: string
): Promise<void> {
  const db = await getPGlite();

  await db.query(
    'UPDATE alerts SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE alert_uuid = $2;',
    [newStatus, alertUUID]
  );

  // Alter table if column missing (safe migration for local IndexedDB)
  try {
    await db.query('ALTER TABLE triage_actions ADD COLUMN IF NOT EXISTS hypothesis_selected VARCHAR(128);');
  } catch (_) {}

  await db.query(
    'INSERT INTO triage_actions (alert_uuid, actor, action_taken, notes, hypothesis_selected) VALUES ($1, $2, $3, $4, $5);',
    [alertUUID, actor, action, notes || '', hypothesisSelected || null]
  );
}

export async function fetchAlertsFromPGlite(filterStatus?: string): Promise<AlertRecord[]> {
  const db = await getPGlite();

  let sql = 'SELECT * FROM alerts';
  const params: any[] = [];
  if (filterStatus && filterStatus !== 'ALL') {
    sql += ' WHERE status = $1';
    params.push(filterStatus);
  }
  sql += ' ORDER BY calculated_score DESC, updated_at DESC;';

  const res = await db.query<any>(sql, params);
  const alerts: AlertRecord[] = [];

  for (const row of res.rows) {
    // Fetch IOCs
    const iocRes = await db.query<any>(
      'SELECT ioc_type, ioc_value FROM alert_iocs WHERE alert_uuid = $1;',
      [row.alert_uuid]
    );

    // Fetch Enrichments
    const enrRes = await db.query<any>(
      'SELECT provider, normalized_score, raw_response FROM enrichment_data WHERE alert_uuid = $1;',
      [row.alert_uuid]
    );

    const score = parseFloat(row.calculated_score) || 0;
    let tier: any = 'LOW';
    if (score >= 80) tier = 'CRITICAL';
    else if (score >= 60) tier = 'HIGH';
    else if (score >= 30) tier = 'MEDIUM';

    alerts.push({
      id: row.id,
      alert_uuid: row.alert_uuid,
      source: row.source,
      event_type: row.event_type,
      severity_raw: row.severity_raw,
      calculated_score: score,
      severity_tier: tier,
      status: row.status,
      created_at: row.created_at,
      updated_at: row.updated_at,
      iocs: iocRes.rows.map((r) => ({ ioc_type: r.ioc_type, ioc_value: r.ioc_value })),
      enrichments: enrRes.rows.map((r) => ({
        provider: r.provider,
        score: parseFloat(r.normalized_score) || 0,
        raw_response: typeof r.raw_response === 'string' ? JSON.parse(r.raw_response) : r.raw_response,
      })),
    });
  }

  return alerts;
}

export async function fetchDashboardMetrics(): Promise<DashboardMetrics> {
  const db = await getPGlite();
  const res = await db.query<any>(`
    SELECT 
      COUNT(*) as total,
      COUNT(*) FILTER (WHERE calculated_score >= 80) as critical_count,
      COUNT(*) FILTER (WHERE calculated_score >= 60 AND calculated_score < 80) as high_count,
      COUNT(*) FILTER (WHERE status = 'CONTAINED' OR status = 'TRIAGED') as contained_count,
      COALESCE(AVG(calculated_score), 0) as avg_score
    FROM alerts;
  `);

  const row = res.rows[0] || {};
  return {
    totalAlerts: parseInt(row.total || '0', 10),
    criticalCount: parseInt(row.critical_count || '0', 10),
    highCount: parseInt(row.high_count || '0', 10),
    containedCount: parseInt(row.contained_count || '0', 10),
    avgScore: Math.round(parseFloat(row.avg_score || '0') * 10) / 10,
  };
}

export async function executeSQLConsole(sql: string): Promise<{ rows: any[]; fields: string[]; durationMs: number }> {
  const db = await getPGlite();
  const start = performance.now();
  const res = await db.query<any>(sql);
  const durationMs = Math.round((performance.now() - start) * 100) / 100;

  const fields = res.fields?.map((f) => f.name) || (res.rows[0] ? Object.keys(res.rows[0]) : []);
  return {
    rows: res.rows || [],
    fields,
    durationMs,
  };
}
