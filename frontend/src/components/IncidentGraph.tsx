'use client';

import React, { useMemo } from 'react';
import { IncidentGroup } from '@/types/alert';
import { Globe, Server, ShieldAlert, ArrowRight, Zap, Terminal } from 'lucide-react';

interface IncidentGraphProps {
  incident: IncidentGroup;
}

export const IncidentGraph: React.FC<IncidentGraphProps> = ({ incident }) => {
  // Extract unique stages
  const stages = useMemo(() => {
    return incident.alerts.map((a, idx) => {
      const primaryIOC = a.iocs?.find((i) => i.ioc_type === 'IP')?.ioc_value || 'Threat Source';
      const targetHost = a.asset_id || 'corp-endpoint';
      const tactic = a.mitre?.tactic || 'Execution';
      const techId = a.mitre?.techniqueId || 'T1204';

      return {
        stageNum: idx + 1,
        alertUUID: a.alert_uuid,
        score: a.calculated_score,
        eventType: a.event_type,
        source: primaryIOC,
        target: targetHost,
        tactic,
        techId,
      };
    });
  }, [incident]);

  return (
    <div className="bg-zinc-50 dark:bg-zinc-950/50 border border-zinc-200 dark:border-zinc-800 rounded-xl p-4 my-3 text-xs overflow-x-auto shadow-inner">
      <div className="flex items-center justify-between mb-3">
        <span className="text-[10px] uppercase font-bold tracking-wider text-zinc-500 dark:text-zinc-400 flex items-center gap-1.5">
          <Zap className="w-3.5 h-3.5 text-amber-500" />
          Attack Graph / Lateral Movement Flow ({stages.length} Nodes)
        </span>
        <span className="text-[10px] text-zinc-400 font-mono">
          Adversary Pivot: {incident.keyEntity}
        </span>
      </div>

      <div className="flex items-center gap-3 min-w-[650px] py-2">
        {stages.map((st, i) => (
          <React.Fragment key={st.alertUUID}>
            {/* Stage Node Box */}
            <div className="flex-1 min-w-[190px] bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-3 shadow-sm hover:border-blue-400 dark:hover:border-blue-600 transition">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 font-bold">
                  STAGE {st.stageNum}
                </span>
                <span
                  className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded ${
                    st.score >= 80
                      ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                      : 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300'
                  }`}
                >
                  {st.score.toFixed(0)} pts
                </span>
              </div>

              {/* Tactic Pill */}
              <div className="text-[10px] font-semibold text-zinc-700 dark:text-zinc-300 mb-1 truncate">
                {st.tactic}
              </div>

              <div className="text-[11px] font-bold text-zinc-900 dark:text-white truncate" title={st.eventType}>
                {st.eventType}
              </div>

              <div className="mt-2 pt-2 border-t border-zinc-100 dark:border-zinc-800 text-[10px] space-y-1 font-mono">
                <div className="flex items-center gap-1 text-zinc-500 truncate">
                  <Globe className="w-3 h-3 text-red-500 shrink-0" />
                  <span className="truncate">{st.source}</span>
                </div>
                <div className="flex items-center gap-1 text-zinc-600 dark:text-zinc-300 truncate">
                  <Server className="w-3 h-3 text-blue-500 shrink-0" />
                  <span className="truncate">{st.target}</span>
                </div>
              </div>
            </div>

            {/* Connecting Pivot Edge */}
            {i < stages.length - 1 && (
              <div className="flex flex-col items-center justify-center shrink-0 text-zinc-400 dark:text-zinc-600">
                <span className="text-[9px] font-mono text-zinc-400">PIVOT</span>
                <ArrowRight className="w-5 h-5 text-blue-500 animate-pulse" />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};
