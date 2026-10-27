export type AlertStatus = 'NEW' | 'ENRICHED' | 'TRIAGED' | 'CONTAINED' | 'DISMISSED';

export type SeverityTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface IOCItem {
  ioc_type: 'IP' | 'HASH' | 'DOMAIN';
  ioc_value: string;
}

export interface CTIResult {
  provider: string;
  score: number;
  raw_response: Record<string, any>;
  malicious_count?: number;
  confidence_score?: number;
  open_ports?: number[];
  vulnerabilities?: string[];
  error?: string;
}

export interface AlertRecord {
  id?: number;
  alert_uuid: string;
  source: string;
  event_type: string;
  severity_raw: string;
  calculated_score: number;
  severity_tier: SeverityTier;
  status: AlertStatus;
  auto_action_taken?: string;
  created_at: string;
  updated_at: string;
  iocs?: IOCItem[];
  enrichments?: CTIResult[];
}

export interface TriageAuditLog {
  id?: number;
  alert_uuid: string;
  actor: string;
  action_taken: string;
  notes?: string;
  performed_at: string;
}

export interface DashboardMetrics {
  totalAlerts: number;
  criticalCount: number;
  highCount: number;
  containedCount: number;
  avgScore: number;
}
