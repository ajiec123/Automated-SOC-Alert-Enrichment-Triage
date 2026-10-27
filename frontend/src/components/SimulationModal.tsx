'use client';

import React, { useState } from 'react';
import { Zap, ShieldAlert, Bug, Flame, Radio, Check } from 'lucide-react';

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

  if (!isOpen) return null;

  const scenarios = [
    {
      id: 'critical_c2',
      title: 'Cobalt Strike C2 Beacon',
      desc: 'High-frequency HTTP beaconing to known malicious IP (118.25.6.39) targeting Domain Controller dc-01.',
      severity: 'CRITICAL',
      icon: ShieldAlert,
      color: 'border-red-500/50 hover:bg-red-950/20 text-red-400',
    },
    {
      id: 'ransomware',
      title: 'Ransomware VSS Shadow Deletion',
      desc: 'Shadow copy wipe command executed alongside malicious file hash on db-prod.internal server.',
      severity: 'CRITICAL',
      icon: Flame,
      color: 'border-rose-500/50 hover:bg-rose-950/20 text-rose-400',
    },
    {
      id: 'log4j',
      title: 'Apache Log4j RCE (CVE-2021-44228)',
      desc: 'JNDI injection exploit pattern detected in HTTP header targeting payment-gw service.',
      severity: 'CRITICAL',
      icon: Bug,
      color: 'border-orange-500/50 hover:bg-orange-950/20 text-orange-400',
    },
    {
      id: 'bruteforce',
      title: 'Distributed SSH Password Spray',
      desc: '300+ failed login attempts within 60s from reputation-flagged IP against dmz-proxy gateway.',
      severity: 'HIGH',
      icon: Radio,
      color: 'border-amber-500/50 hover:bg-amber-950/20 text-amber-400',
    },
    {
      id: 'portscan',
      title: 'SYN Stealth Network Port Scan',
      desc: 'Rapid reconnaissance scan across multiple ports on corp-workstation endpoint.',
      severity: 'LOW',
      icon: Zap,
      color: 'border-emerald-500/50 hover:bg-emerald-950/20 text-emerald-400',
    },
  ];

  const handleSimulate = async (scenarioId: string) => {
    setLoadingScenario(scenarioId);
    setSuccessMsg(null);

    const apiUrl =
      process.env.NEXT_PUBLIC_API_URL ||
      `http://${window.location.hostname}:8080/api/v1/alerts/simulate`;

    try {
      const resp = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioId }),
      });

      if (!resp.ok) {
        throw new Error(`Server returned ${resp.status}`);
      }

      const res = await resp.json();
      setSuccessMsg(`Simulated alert ${res.alert?.alert_uuid || ''} generated and enriched!`);

      if (onAlertGenerated) {
        onAlertGenerated();
      }

      setTimeout(() => {
        setSuccessMsg(null);
      }, 4000);
    } catch (err: any) {
      console.error('Failed to trigger simulation:', err);
    } finally {
      setLoadingScenario(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl">
        <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-400" />
            <h3 className="text-base font-bold text-white">
              SOC Threat Telemetry Simulator
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-white px-2.5 py-1 rounded-lg bg-zinc-800/80 hover:bg-zinc-800 text-xs transition"
          >
            ✕ Close
          </button>
        </div>

        <div className="p-6 space-y-3">
          <p className="text-xs text-zinc-400">
            Inject realistic SIEM alerts into the Golang High-Throughput Core. Each alert is enriched concurrently across VirusTotal, AbuseIPDB, and Shodan before streaming live to this dashboard.
          </p>

          {successMsg && (
            <div className="p-3 bg-emerald-950/60 border border-emerald-800 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
              <Check className="w-4 h-4 text-emerald-400" />
              <span>{successMsg}</span>
            </div>
          )}

          <div className="space-y-2 mt-4">
            {scenarios.map((sc) => {
              const Icon = sc.icon;
              return (
                <div
                  key={sc.id}
                  className={`border rounded-xl p-3.5 bg-zinc-900/50 flex items-center justify-between gap-4 transition-all ${sc.color}`}
                >
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-zinc-900 border border-zinc-800 mt-0.5">
                      <Icon className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-sm font-semibold text-white">
                          {sc.title}
                        </h4>
                        <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                          {sc.severity}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400 mt-0.5">{sc.desc}</p>
                    </div>
                  </div>

                  <button
                    onClick={() => handleSimulate(sc.id)}
                    disabled={loadingScenario !== null}
                    className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition shrink-0 disabled:opacity-50"
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
