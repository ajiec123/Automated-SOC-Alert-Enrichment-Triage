'use client';

import React, { useState } from 'react';
import { IncidentGroup, AlertRecord } from '@/types/alert';
import {
  Flame,
  ShieldAlert,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp,
  Globe,
  Server,
  ArrowRight,
  Crosshair,
  CheckCircle2,
  Activity,
  Zap,
} from 'lucide-react';
import { AlertCard } from './AlertCard';
import { IncidentGraph } from './IncidentGraph';

interface IncidentStorylineProps {
  incidents: IncidentGroup[];
  onActionComplete?: () => void;
  onSelectIOC?: (ioc: { ioc_type: 'IP' | 'HASH' | 'DOMAIN'; ioc_value: string }) => void;
  onTriggerPlaybook?: (action: string, alertUUID: string) => void;
}

export const IncidentStoryline: React.FC<IncidentStorylineProps> = ({
  incidents,
  onActionComplete,
  onSelectIOC,
  onTriggerPlaybook,
}) => {
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(
    incidents[0]?.id || null
  );

  if (incidents.length === 0) {
    return null;
  }

  const getTierBadge = (tier: string) => {
    switch (tier) {
      case 'CRITICAL':
        return 'bg-red-600 text-white';
      case 'HIGH':
        return 'bg-orange-500 text-white';
      case 'MEDIUM':
        return 'bg-amber-500 text-black';
      default:
        return 'bg-emerald-600 text-white';
    }
  };

  return (
    <div className="space-y-4">
      {incidents.map((inc) => {
        const isExpanded = expandedIncidentId === inc.id;
        const isCritical = inc.highestScore >= 80;

        return (
          <div
            key={inc.id}
            className={`border rounded-xl bg-white dark:bg-zinc-900/80 shadow-sm transition-all duration-200 overflow-hidden ${
              isCritical
                ? 'border-red-300 dark:border-red-900/60'
                : 'border-zinc-200 dark:border-zinc-800'
            }`}
          >
            {/* Incident Header Accordion Bar */}
            <div
              onClick={() => setExpandedIncidentId(isExpanded ? null : inc.id)}
              className="p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/40 transition"
            >
              <div className="flex items-center gap-3">
                <div
                  className={`p-2.5 rounded-xl border flex items-center justify-center shrink-0 ${
                    isCritical
                      ? 'bg-red-500/10 border-red-500/30 text-red-600 dark:text-red-400'
                      : 'bg-blue-500/10 border-blue-500/30 text-blue-600 dark:text-blue-400'
                  }`}
                >
                  <Flame className="w-5 h-5" />
                </div>

                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs px-2 py-0.5 rounded font-bold bg-zinc-100 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200">
                      {inc.id}
                    </span>
                    <span
                      className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full ${getTierBadge(
                        inc.highestTier
                      )}`}
                    >
                      {inc.highestTier} INCIDENT
                    </span>
                    <span className="text-xs text-zinc-500 dark:text-zinc-400 flex items-center gap-1 font-mono">
                      <Clock className="w-3 h-3" />
                      {new Date(inc.startTime).toLocaleTimeString()} &rarr;{' '}
                      {new Date(inc.lastSeenTime).toLocaleTimeString()}
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-zinc-900 dark:text-white mt-1 flex items-center gap-2">
                    {inc.title}
                  </h3>

                  <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                    {inc.hypothesisSummary}
                  </p>
                </div>
              </div>

              {/* Stats & Expand Controls */}
              <div className="flex items-center gap-3 self-end md:self-center shrink-0">
                <div className="text-right">
                  <div className="text-[10px] uppercase tracking-wider text-zinc-500 dark:text-zinc-400 font-medium">
                    Correlated Alerts
                  </div>
                  <div className="text-lg font-black text-zinc-900 dark:text-white font-mono flex items-center justify-end gap-1.5">
                    <Layers className="w-4 h-4 text-blue-500" />
                    {inc.alerts.length} Stage{inc.alerts.length > 1 ? 's' : ''}
                  </div>
                </div>

                <div
                  className={`w-11 h-11 rounded-xl flex items-center justify-center font-mono font-bold text-sm shadow-sm ${getTierBadge(
                    inc.highestTier
                  )}`}
                >
                  {inc.highestScore.toFixed(0)}
                </div>

                <div className="p-1 rounded-lg text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200">
                  {isExpanded ? (
                    <ChevronUp className="w-5 h-5" />
                  ) : (
                    <ChevronDown className="w-5 h-5" />
                  )}
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Kill Chain Horizontal Timeline Badges */}
            <div className="px-4 py-2.5 bg-zinc-50 dark:bg-zinc-950/40 border-t border-zinc-200 dark:border-zinc-800 flex flex-wrap items-center gap-2 text-xs">
              <span className="text-[11px] font-bold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider flex items-center gap-1">
                <Crosshair className="w-3.5 h-3.5 text-blue-500" />
                Kill-Chain Progression:
              </span>

              {inc.mitreTactics.map((tactic, idx) => (
                <div key={idx} className="flex items-center gap-1.5">
                  <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold bg-white text-zinc-800 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-200 dark:border-zinc-700 border shadow-2xs">
                    {tactic}
                  </span>
                  {idx < inc.mitreTactics.length - 1 && (
                    <ArrowRight className="w-3 h-3 text-zinc-400" />
                  )}
                </div>
              ))}
            </div>

            {/* Expanded Multi-Stage Attack Storyline */}
            {isExpanded && (
              <div className="p-5 border-t border-zinc-200 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-950/30 space-y-4">
                {/* Visual Lateral Movement Attack Graph */}
                <IncidentGraph incident={inc} />

                <div className="flex items-center justify-between pb-2">
                  <h4 className="text-xs uppercase font-extrabold tracking-wider text-zinc-700 dark:text-zinc-300 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-blue-500" />
                    Chronological Multi-Stage Attack Telemetry ({inc.alerts.length} Events)
                  </h4>
                  <span className="text-xs text-zinc-500 font-mono">
                    Entity: {inc.keyEntity} ({inc.entityType})
                  </span>
                </div>

                <div className="relative pl-6 space-y-4 before:content-[''] before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-blue-300 dark:before:bg-blue-900">
                  {inc.alerts.map((alert, stageIdx) => (
                    <div key={alert.alert_uuid} className="relative">
                      {/* Timeline Marker Pin */}
                      <span className="absolute -left-6 top-5 w-4 h-4 rounded-full bg-blue-600 border-2 border-white dark:border-zinc-900 flex items-center justify-center text-[8px] font-bold text-white">
                        {stageIdx + 1}
                      </span>

                      {/* Render Alert Card */}
                      <AlertCard
                        alert={alert}
                        onActionComplete={onActionComplete}
                        onSelectIOC={onSelectIOC}
                        onTriggerPlaybook={onTriggerPlaybook}
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
