'use client';

import React, { useState } from 'react';
import { Zap, ShieldAlert, Bug, Flame, Radio, Check, AlertTriangle } from 'lucide-react';
import { upsertAlertInPGlite } from '@/lib/pglite';
import { AlertRecord } from '@/types/alert';

interface SimulationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAlertGenerated?: () => void;
}

export const SimulationModal: React.FC<SimulationModalProps> = ({
  isOpen,
  onClose,
  onAlertGenerated,
}) => {
  const [loadingScenario, setLoadingScenario] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const scenarios = [
    {
      id: 'critical_c2',
      title: 'Cobalt Strike C2 Beacon',
      desc: 'High-frequency HTTP beaconing to known malicious IP (118.25.6.39) targeting Domain Controller dc-01.',
      severity: 'CRITICAL',
      icon: ShieldAlert,
      color: 'border-red-300 dark:border-red-500/50 bg-red-50/50 hover:bg-red-50 dark:bg-zinc-900/50 dark:hover:bg-red-950/20 text-red-600 dark:text-red-400',
    },
    {
      id: 'ransomware',
      title: 'Ransomware VSS Shadow Deletion',
      desc: 'Shadow copy wipe command executed alongside malicious file hash on db-prod.internal server.',
      severity: 'CRITICAL',
      icon: Flame,
      color: 'border-rose-300 dark:border-rose-500/50 bg-rose-50/50 hover:bg-rose-50 dark:bg-zinc-900/50 dark:hover:bg-rose-950/20 text-rose-600 dark:text-rose-400',
    },
    {
      id: 'log4j',
      title: 'Apache Log4j RCE (CVE-2021-44228)',
      desc: 'JNDI injection exploit pattern detected in HTTP header targeting payment-gw service.',
      severity: 'CRITICAL',
      icon: Bug,
      color: 'border-orange-300 dark:border-orange-500/50 bg-orange-50/50 hover:bg-orange-50 dark:bg-zinc-900/50 dark:hover:bg-orange-950/20 text-orange-600 dark:text-orange-400',
    },
    {
      id: 'bruteforce',
      title: 'Distributed SSH Password Spray',
      desc: '300+ failed login attempts within 60s from reputation-flagged IP against dmz-proxy gateway.',
      severity: 'HIGH',
      icon: Radio,
      color: 'border-amber-300 dark:border-amber-500/50 bg-amber-50/50 hover:bg-amber-50 dark:bg-zinc-900/50 dark:hover:bg-amber-950/20 text-amber-600 dark:text-amber-400',
    },
    {
      id: 'portscan',
      title: 'SYN Stealth Network Port Scan',
      desc: 'Rapid reconnaissance scan across multiple ports on corp-workstation endpoint.',
      severity: 'LOW',
      icon: Zap,
      color: 'border-emerald-300 dark:border-emerald-500/50 bg-emerald-50/50 hover:bg-emerald-50 dark:bg-zinc-900/50 dark:hover:bg-emerald-950/20 text-emerald-600 dark:text-emerald-400',
    },
  ];

  // Client-side fallback generator if backend core is offline
  const generateLocalSimulatedAlert = (scenarioId: string): AlertRecord => {
    const randomHex = Math.random().toString(36).substring(2, 8);
    const uuid = `ALT-${Math.floor(100000 + Math.random() * 900000)}-${randomHex}`;
    const now = new Date().toISOString();

    switch (scenarioId) {
      case 'ransomware':
        return {
          alert_uuid: uuid,
          source: 'Wazuh SIEM',
          event_type: 'Ransomware VSS Shadow Deletion & File Encryption',
          severity_raw: 'CRITICAL',
          calculated_score: 94.0,
          severity_tier: 'CRITICAL',
          status: 'CONTAINED',
          auto_action_taken: 'Automated EDR Host Quarantine & VSS Rollback Protection',
          created_at: now,
          updated_at: now,
          iocs: [
            { ioc_type: 'HASH', ioc_value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' },
            { ioc_type: 'IP', ioc_value: '10.0.4.112' },
          ],
          enrichments: [
            { provider: 'VirusTotal', score: 98.0, raw_response: { positives: 68, total: 72 } },
            { provider: 'AbuseIPDB', score: 85.0, raw_response: { abuseConfidenceScore: 85, countryCode: 'US' } },
            { provider: 'Shodan', score: 70.0, raw_response: { ports: [445, 3389], vulns: ['CVE-2017-0144'] } },
          ],
        };

      case 'log4j':
        return {
          alert_uuid: uuid,
          source: 'Wazuh SIEM',
          event_type: 'Apache Log4j RCE (CVE-2021-44228) Injection Attack',
          severity_raw: 'CRITICAL',
          calculated_score: 92.5,
          severity_tier: 'CRITICAL',
          status: 'CONTAINED',
          auto_action_taken: 'Edge WAF Rule Applied & Malicious IP Blocked',
          created_at: now,
          updated_at: now,
          iocs: [
            { ioc_type: 'IP', ioc_value: '45.33.32.156' },
            { ioc_type: 'DOMAIN', ioc_value: 'jndi-exploit-server.net' },
          ],
          enrichments: [
            { provider: 'VirusTotal', score: 88.0, raw_response: { positives: 55, total: 72 } },
            { provider: 'AbuseIPDB', score: 98.0, raw_response: { abuseConfidenceScore: 98, countryCode: 'DE' } },
            { provider: 'Shodan', score: 84.0, raw_response: { ports: [80, 1389, 8080], vulns: ['CVE-2021-44228'] } },
          ],
        };

      case 'bruteforce':
        return {
          alert_uuid: uuid,
          source: 'Suricata NIDS',
          event_type: 'Distributed SSH Password Spray Attack',
          severity_raw: 'HIGH',
          calculated_score: 74.0,
          severity_tier: 'HIGH',
          status: 'ENRICHED',
          created_at: now,
          updated_at: now,
          iocs: [{ ioc_type: 'IP', ioc_value: '198.51.100.42' }],
          enrichments: [
            { provider: 'VirusTotal', score: 62.0, raw_response: { positives: 44, total: 72 } },
            { provider: 'AbuseIPDB', score: 92.0, raw_response: { abuseConfidenceScore: 92, countryCode: 'RU' } },
            { provider: 'Shodan', score: 60.0, raw_response: { ports: [22, 2222], vulns: [] } },
          ],
        };

      case 'portscan':
        return {
          alert_uuid: uuid,
          source: 'Zeek Bro IDS',
          event_type: 'SYN Stealth Network Port Scan',
          severity_raw: 'LOW',
          calculated_score: 28.0,
          severity_tier: 'LOW',
          status: 'NEW',
          created_at: now,
          updated_at: now,
          iocs: [{ ioc_type: 'IP', ioc_value: '192.168.1.185' }],
          enrichments: [
            { provider: 'VirusTotal', score: 10.0, raw_response: { positives: 1, total: 72 } },
            { provider: 'AbuseIPDB', score: 0.0, raw_response: { abuseConfidenceScore: 0, countryCode: 'LOCAL' } },
            { provider: 'Shodan', score: 15.0, raw_response: { ports: [80, 443], vulns: [] } },
          ],
        };

      default: // critical_c2
        return {
          alert_uuid: uuid,
          source: 'Wazuh SIEM',
          event_type: 'Cobalt Strike C2 Malleable HTTPS Beaconing',
          severity_raw: 'CRITICAL',
          calculated_score: 95.0,
          severity_tier: 'CRITICAL',
          status: 'CONTAINED',
          auto_action_taken: 'Egress Traffic Dropped & C2 Domain Blacklisted',
          created_at: now,
          updated_at: now,
          iocs: [
            { ioc_type: 'IP', ioc_value: '118.25.6.39' },
            { ioc_type: 'DOMAIN', ioc_value: 'telemetry-update-services.org' },
          ],
          enrichments: [
            { provider: 'VirusTotal', score: 85.0, raw_response: { positives: 61, total: 72 } },
            { provider: 'AbuseIPDB', score: 96.0, raw_response: { abuseConfidenceScore: 96, countryCode: 'CN' } },
            { provider: 'Shodan', score: 90.0, raw_response: { ports: [80, 443, 4444], vulns: ['CVE-2021-44228'] } },
          ],
        };
    }
  };

  const handleSimulate = async (scenarioId: string) => {
    setLoadingScenario(scenarioId);
    setSuccessMsg(null);
    setErrorMsg(null);

    const apiUrl =
      process.env.NEXT_PUBLIC_API_URL ||
      `http://${window.location.hostname}:8080/api/v1/alerts/simulate`;

    let generatedAlert: AlertRecord | null = null;

    try {
      // 1. Try hitting the Go Backend Ingestion API with a 2.5s timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500);

      const resp = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioId }),
        signal: controller.signal,
      }).catch((fetchErr) => {
        console.warn('Backend simulate endpoint unreachable or timed out:', fetchErr);
        return null;
      });

      clearTimeout(timeoutId);

      if (resp && resp.ok) {
        const res = await resp.json();
        const incoming = res.alert;
        if (incoming) {
          // Normalize to AlertRecord schema
          generatedAlert = {
            alert_uuid: incoming.alert_uuid || incoming.AlertUUID,
            source: incoming.source || incoming.Source || 'Wazuh SIEM',
            event_type: incoming.event_type || incoming.EventType || 'Simulated Threat Telemetry',
            severity_raw: incoming.severity_raw || incoming.SeverityRaw || 'HIGH',
            calculated_score: incoming.calculated_score || incoming.CalculatedScore || 75,
            severity_tier: incoming.severity_tier || incoming.SeverityTier || 'HIGH',
            status: incoming.status || incoming.Status || 'ENRICHED',
            auto_action_taken: incoming.auto_action_taken || incoming.AutoActionTaken,
            created_at: incoming.created_at || incoming.CreatedAt || new Date().toISOString(),
            updated_at: incoming.updated_at || incoming.UpdatedAt || new Date().toISOString(),
            iocs: (incoming.iocs || incoming.IOCs || []).map((i: any) => ({
              ioc_type: i.type || i.ioc_type,
              ioc_value: i.value || i.ioc_value,
            })),
            enrichments: (incoming.enrichments || incoming.Enrichments || []).map((e: any) => ({
              provider: e.provider || e.Provider,
              score: e.score || e.Score || 0,
              raw_response: e.raw_response || e.RawResponse || {},
            })),
          };
        }
      }
    } catch (err: any) {
      console.warn('Error talking to backend simulation:', err);
    }

    // 2. If Go Backend didn't return an alert (e.g. backend not currently running on :8080),
    // immediately generate realistic telemetry on client side and commit directly to PGlite WASM
    if (!generatedAlert) {
      generatedAlert = generateLocalSimulatedAlert(scenarioId);
    }

    try {
      // 3. Guarantee immediate persistence into local PGlite PostgreSQL WASM Engine
      await upsertAlertInPGlite(generatedAlert);

      setSuccessMsg(`Simulated alert ${generatedAlert.alert_uuid} injected & enriched!`);

      // Trigger dashboard reload
      if (onAlertGenerated) {
        onAlertGenerated();
      }

      setTimeout(() => {
        setSuccessMsg(null);
      }, 4000);
    } catch (dbErr: any) {
      console.error('Failed to write simulated alert into PGlite:', dbErr);
      setErrorMsg(`Failed to store alert: ${dbErr?.message || 'Database error'}`);
    } finally {
      setLoadingScenario(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl">
        <div className="px-6 py-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between bg-zinc-50 dark:bg-zinc-900/60">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-500 dark:text-amber-400" />
            <h3 className="text-base font-bold text-zinc-900 dark:text-white">
              SOC Threat Telemetry Simulator
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white px-2.5 py-1 rounded-lg bg-zinc-200/60 hover:bg-zinc-200 dark:bg-zinc-800/80 dark:hover:bg-zinc-800 text-xs transition"
          >
            ✕ Close
          </button>
        </div>

        <div className="p-6 space-y-3">
          <p className="text-xs text-zinc-600 dark:text-zinc-400">
            Inject realistic SIEM alerts into the detection pipeline. Each scenario generates full telemetry, CTI threat intelligence enrichments, and automatically updates your client-side PGlite database and live dashboard stream.
          </p>

          {successMsg && (
            <div className="p-3 bg-emerald-100 border border-emerald-300 text-emerald-800 dark:bg-emerald-950/60 dark:border-emerald-800 dark:text-emerald-300 rounded-lg text-xs flex items-center gap-2">
              <Check className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {errorMsg && (
            <div className="p-3 bg-red-100 border border-red-300 text-red-800 dark:bg-red-950/60 dark:border-red-800 dark:text-red-300 rounded-lg text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="space-y-2 mt-4">
            {scenarios.map((sc) => {
              const Icon = sc.icon;
              return (
                <div
                  key={sc.id}
                  className={`border rounded-xl p-3.5 flex items-center justify-between gap-4 transition-all shadow-sm ${sc.color}`}
                >
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 shadow-sm mt-0.5">
                      <Icon className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-sm font-semibold text-zinc-900 dark:text-white">
                          {sc.title}
                        </h4>
                        <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                          {sc.severity}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">{sc.desc}</p>
                    </div>
                  </div>

                  <button
                    onClick={() => handleSimulate(sc.id)}
                    disabled={loadingScenario !== null}
                    className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition shrink-0 disabled:opacity-50 shadow-sm"
                  >
                    {loadingScenario === sc.id ? 'Ingesting...' : 'Fire Alert'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
