'use client';

import React, { useState } from 'react';
import { AlertRecord, AlertStatus } from '@/types/alert';
import { recordTriageInPGlite } from '@/lib/pglite';
import {
  ShieldAlert,
  ShieldCheck,
  Ban,
  Activity,
  Globe,
  Hash,
  Terminal,
  CheckCircle2,
  XCircle,
  Cpu,
  Clock,
} from 'lucide-react';

interface AlertCardProps {
  alert: AlertRecord;
  onActionComplete?: () => void;
}

export const AlertCard: React.FC<AlertCardProps> = ({ alert, onActionComplete }) => {
  const [loadingAction, setLoadingAction] = useState<string | null>(null);

  const getTierColor = (score: number) => {
    if (score >= 80) return 'text-red-600 dark:text-red-400 border-red-300 dark:border-red-500/50 bg-red-50/70 dark:bg-red-950/20';
    if (score >= 60) return 'text-orange-600 dark:text-orange-400 border-orange-300 dark:border-orange-500/50 bg-orange-50/70 dark:bg-orange-950/20';
    if (score >= 30) return 'text-amber-600 dark:text-yellow-400 border-amber-300 dark:border-yellow-500/50 bg-amber-50/70 dark:bg-yellow-950/20';
    return 'text-emerald-600 dark:text-emerald-400 border-emerald-300 dark:border-emerald-500/50 bg-emerald-50/70 dark:bg-emerald-950/20';
  };

  const getScoreBadge = (score: number) => {
    if (score >= 80) return 'bg-red-600 text-white';
    if (score >= 60) return 'bg-orange-500 text-white';
    if (score >= 30) return 'bg-yellow-500 text-black';
    return 'bg-emerald-600 text-white';
  };

  const getStatusBadge = (status: AlertStatus) => {
    switch (status) {
      case 'CONTAINED':
        return 'bg-purple-100 text-purple-700 border-purple-200 dark:bg-purple-900/60 dark:text-purple-300 dark:border-purple-700/60';
      case 'TRIAGED':
        return 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/60 dark:text-blue-300 dark:border-blue-700/60';
      case 'DISMISSED':
        return 'bg-zinc-200 text-zinc-700 border-zinc-300 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700';
      case 'ENRICHED':
        return 'bg-cyan-100 text-cyan-700 border-cyan-200 dark:bg-cyan-900/60 dark:text-cyan-300 dark:border-cyan-700/60';
      default:
        return 'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-900/60 dark:text-amber-300 dark:border-amber-700/60';
    }
  };

  const handleAction = async (action: string) => {
    setLoadingAction(action);
    const backendUrl =
      process.env.NEXT_PUBLIC_API_URL ||
      `http://${window.location.hostname}:8080/api/v1/triage`;

    let targetStatus = 'TRIAGED';
    if (action === 'block_ip' || action === 'isolate_host') targetStatus = 'CONTAINED';
    if (action === 'dismiss') targetStatus = 'DISMISSED';

    try {
      // 1. Notify Backend API
      await fetch(backendUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_uuid: alert.alert_uuid,
          action,
          actor: 'SOC Web Analyst',
          notes: `Action [${action}] triggered from Operations Dashboard Console`,
        }),
      }).catch((e) => console.warn('Backend triage call failed, updating local PGlite:', e));

      // 2. Update local PGlite WASM
      await recordTriageInPGlite(
        alert.alert_uuid,
        'SOC Web Analyst',
        action,
        targetStatus,
        `Triggered: ${action}`
      );

      if (onActionComplete) onActionComplete();
    } catch (err) {
      console.error('Failed to execute triage action:', err);
    } finally {
      setLoadingAction(null);
    }
  };

  return (
    <div
      className={`border rounded-xl p-5 mb-4 shadow-sm transition-all duration-200 hover:shadow-md ${getTierColor(
        alert.calculated_score
      )}`}
    >
      {/* Top Header Row */}
      <div className="flex flex-wrap items-start justify-between gap-3 pb-3 border-b border-zinc-200/80 dark:border-zinc-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 shadow-sm">
            {alert.calculated_score >= 80 ? (
              <ShieldAlert className="w-6 h-6 text-red-500 animate-pulse" />
            ) : alert.status === 'CONTAINED' ? (
              <ShieldCheck className="w-6 h-6 text-purple-500 dark:text-purple-400" />
            ) : (
              <Activity className="w-6 h-6 text-blue-500 dark:text-blue-400" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-zinc-200/80 text-zinc-800 dark:bg-zinc-800/90 dark:text-zinc-300 font-semibold">
                {alert.alert_uuid}
              </span>
              <span className="text-xs text-zinc-500 dark:text-zinc-400 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {new Date(alert.created_at).toLocaleTimeString()}
              </span>
              <span
                className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full border ${getStatusBadge(
                  alert.status
                )}`}
              >
                {alert.status}
              </span>
            </div>
            <h3 className="text-base font-semibold text-zinc-900 dark:text-white mt-1">
              {alert.event_type}
            </h3>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Telemetry Source:{' '}
              <span className="text-zinc-700 dark:text-zinc-200 font-medium">{alert.source}</span>
            </p>
          </div>
        </div>

        {/* Dynamic Composite Risk Score Meter */}
        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-400 font-medium">
              Composite Risk Score
            </div>
            <div className="text-2xl font-black text-zinc-900 dark:text-white font-mono flex items-center justify-end gap-1">
              {alert.calculated_score.toFixed(1)}
              <span className="text-xs text-zinc-400 dark:text-zinc-500 font-normal">/ 100</span>
            </div>
          </div>
          <div
            className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold text-sm shadow-md ${getScoreBadge(
              alert.calculated_score
            )}`}
          >
            {alert.calculated_score >= 80
              ? 'CRIT'
              : alert.calculated_score >= 60
              ? 'HIGH'
              : alert.calculated_score >= 30
              ? 'MED'
              : 'LOW'}
          </div>
        </div>
      </div>

      {/* Indicators of Compromise (IOCs) */}
      {alert.iocs && alert.iocs.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2 items-center">
          <span className="text-xs text-zinc-500 dark:text-zinc-400 font-medium flex items-center gap-1 mr-1">
            <Terminal className="w-3.5 h-3.5 text-zinc-500 dark:text-zinc-400" />
            Indicators (IOCs):
          </span>
          {alert.iocs.map((ioc, idx) => (
            <div
              key={idx}
              className="flex items-center gap-1.5 bg-white dark:bg-zinc-900/90 border border-zinc-200 dark:border-zinc-700/80 px-2.5 py-1 rounded text-xs font-mono text-zinc-800 dark:text-zinc-200 shadow-sm"
            >
              {ioc.ioc_type === 'IP' ? (
                <Globe className="w-3 h-3 text-blue-500 dark:text-blue-400" />
              ) : (
                <Hash className="w-3 h-3 text-amber-500 dark:text-amber-400" />
              )}
              <span className="text-[10px] text-zinc-500 dark:text-zinc-400 font-bold uppercase">
                {ioc.ioc_type}:
              </span>
              <span>{ioc.ioc_value}</span>
            </div>
          ))}
        </div>
      )}

      {/* Threat Intelligence Enrichment Cards (VT, AbuseIPDB, Shodan) */}
      {alert.enrichments && alert.enrichments.length > 0 && (
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          {alert.enrichments.map((enr, i) => (
            <div
              key={i}
              className="bg-white/80 dark:bg-zinc-900/80 border border-zinc-200 dark:border-zinc-800 rounded-lg p-3 text-xs shadow-sm"
            >
              <div className="flex items-center justify-between text-zinc-700 dark:text-zinc-300 font-medium mb-1">
                <span className="flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
                  {enr.provider}
                </span>
                <span
                  className={`font-mono font-bold ${
                    enr.score >= 70
                      ? 'text-red-600 dark:text-red-400'
                      : enr.score >= 40
                      ? 'text-orange-600 dark:text-orange-400'
                      : 'text-emerald-600 dark:text-emerald-400'
                  }`}
                >
                  {enr.score.toFixed(0)}/100
                </span>
              </div>
              <div className="text-[11px] text-zinc-500 dark:text-zinc-400 space-y-0.5">
                {enr.provider === 'VirusTotal' && (
                  <div>
                    Detections:{' '}
                    <span className="text-zinc-900 dark:text-white font-mono font-semibold">
                      {enr.raw_response?.positives ?? enr.malicious_count ?? 0} /{' '}
                      {enr.raw_response?.total ?? 72}
                    </span>
                  </div>
                )}
                {enr.provider === 'AbuseIPDB' && (
                  <div>
                    Confidence:{' '}
                    <span className="text-zinc-900 dark:text-white font-mono font-semibold">
                      {enr.raw_response?.abuseConfidenceScore ?? enr.confidence_score ?? 0}%
                    </span>{' '}
                    ({enr.raw_response?.countryCode || 'N/A'})
                  </div>
                )}
                {enr.provider === 'Shodan' && (
                  <div>
                    Ports:{' '}
                    <span className="text-zinc-900 dark:text-white font-mono font-semibold">
                      {(enr.raw_response?.ports || enr.open_ports || []).slice(0, 3).join(', ') ||
                        'None'}
                    </span>
                    {(enr.raw_response?.vulns || enr.vulnerabilities || []).length > 0 && (
                      <span className="text-red-600 dark:text-red-400 ml-1 font-mono">
                        ({(enr.raw_response?.vulns || enr.vulnerabilities).length} CVEs)
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Auto-Mitigation / Automated SOAR Workflow Notice */}
      {alert.auto_action_taken && (
        <div className="mt-3 text-xs bg-white/70 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded p-2 text-zinc-700 dark:text-zinc-300 flex items-center gap-2 shadow-sm">
          <Activity className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400 shrink-0" />
          <span>{alert.auto_action_taken}</span>
        </div>
      )}

      {/* Interactive Triage Controls */}
      <div className="mt-4 pt-3 border-t border-zinc-200/80 dark:border-zinc-800/80 flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs text-zinc-500 dark:text-zinc-400 font-medium">Analyst Remediation Actions:</span>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => handleAction('block_ip')}
            disabled={loadingAction !== null || alert.status === 'CONTAINED'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white transition disabled:opacity-50 shadow-sm"
          >
            <Ban className="w-3.5 h-3.5" />
            {loadingAction === 'block_ip' ? 'Applying...' : '🚫 Block IP'}
          </button>

          <button
            onClick={() => handleAction('isolate_host')}
            disabled={loadingAction !== null || alert.status === 'CONTAINED'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-purple-700 hover:bg-purple-600 text-white transition disabled:opacity-50 shadow-sm"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            {loadingAction === 'isolate_host' ? 'Isolating...' : '🛡️ Isolate Host'}
          </button>

          <button
            onClick={() => handleAction('resolve')}
            disabled={loadingAction !== null || alert.status === 'TRIAGED'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition disabled:opacity-50 shadow-sm"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            {loadingAction === 'resolve' ? 'Updating...' : '✅ Mark Triaged'}
          </button>

          <button
            onClick={() => handleAction('dismiss')}
            disabled={loadingAction !== null || alert.status === 'DISMISSED'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-200 hover:bg-zinc-300 text-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 dark:text-zinc-300 transition disabled:opacity-50 shadow-sm"
          >
            <XCircle className="w-3.5 h-3.5" />
            {loadingAction === 'dismiss' ? 'Dismissing...' : '❌ Dismiss'}
          </button>
        </div>
      </div>
    </div>
  );
};
