'use client';

import React, { useState } from 'react';
import { AlertRecord } from '@/types/alert';
import { getMitreAttackForAlert, MITRE_TACTIC_ORDER } from '@/lib/mitre';
import { ShieldAlert, Crosshair, ExternalLink, Activity } from 'lucide-react';

interface MitreHeatmapProps {
  alerts: AlertRecord[];
  onSelectTechnique?: (techniqueId: string) => void;
}

export const MitreHeatmap: React.FC<MitreHeatmapProps> = ({ alerts, onSelectTechnique }) => {
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

  // Group alerts by tactic and technique
  const tacticMap: Record<string, { count: number; maxScore: number; techniques: Map<string, { count: number; name: string; score: number }> }> = {};

  // Initialize ordered tactics
  MITRE_TACTIC_ORDER.forEach((tactic) => {
    tacticMap[tactic] = { count: 0, maxScore: 0, techniques: new Map() };
  });

  alerts.forEach((alert) => {
    const mitre = getMitreAttackForAlert(alert);
    if (!tacticMap[mitre.tactic]) {
      tacticMap[mitre.tactic] = { count: 0, maxScore: 0, techniques: new Map() };
    }

    const tObj = tacticMap[mitre.tactic];
    tObj.count += 1;
    tObj.maxScore = Math.max(tObj.maxScore, alert.calculated_score);

    const techKey = mitre.techniqueId;
    const existingTech = tObj.techniques.get(techKey) || { count: 0, name: mitre.techniqueName, score: 0 };
    existingTech.count += 1;
    existingTech.score = Math.max(existingTech.score, alert.calculated_score);
    tObj.techniques.set(techKey, existingTech);
  });

  const getTacticColor = (count: number, maxScore: number) => {
    if (count === 0) return 'bg-zinc-100/60 dark:bg-zinc-900/40 border-zinc-200 dark:border-zinc-800/80 text-zinc-400 dark:text-zinc-600';
    if (maxScore >= 80) return 'bg-red-500/15 border-red-500/40 text-red-600 dark:text-red-400 shadow-sm';
    if (maxScore >= 60) return 'bg-orange-500/15 border-orange-500/40 text-orange-600 dark:text-orange-400 shadow-sm';
    return 'bg-blue-500/15 border-blue-500/40 text-blue-600 dark:text-blue-400 shadow-sm';
  };

  return (
    <div className="bg-white dark:bg-zinc-900/70 border border-zinc-200 dark:border-zinc-800 rounded-xl p-4 shadow-sm mb-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-zinc-200 dark:border-zinc-800">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 bg-red-100 text-red-600 dark:bg-red-950/60 dark:text-red-400 rounded-lg">
            <Crosshair className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-zinc-900 dark:text-white flex items-center gap-2">
              MITRE ATT&amp;CK&reg; Enterprise Kill-Chain Matrix
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300 border border-red-200 dark:border-red-800">
                Adversary TTP Correlation
              </span>
            </h3>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Correlates ingested alerts across adversary tactics to uncover multi-stage attack campaigns.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-red-500" />
            <span className="text-zinc-600 dark:text-zinc-400 text-[11px]">Critical (≥80)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-orange-500" />
            <span className="text-zinc-600 dark:text-zinc-400 text-[11px]">High (60-79)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-blue-500" />
            <span className="text-zinc-600 dark:text-zinc-400 text-[11px]">Medium/Low</span>
          </div>
        </div>
      </div>

      {/* Kill Chain Horizontal Pipeline Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-2 overflow-x-auto pb-1">
        {MITRE_TACTIC_ORDER.map((tactic) => {
          const data = tacticMap[tactic] || { count: 0, maxScore: 0, techniques: new Map() };
          const isActive = data.count > 0;
          const isSelected = selectedTactic === tactic;

          return (
            <div
              key={tactic}
              onClick={() => setSelectedTactic(isSelected ? null : tactic)}
              className={`border rounded-lg p-2.5 transition flex flex-col justify-between cursor-pointer ${getTacticColor(
                data.count,
                data.maxScore
              )} ${isSelected ? 'ring-2 ring-blue-500' : ''}`}
            >
              <div>
                <div className="text-[10px] uppercase font-bold tracking-wider truncate mb-1">
                  {tactic}
                </div>
                <div className="flex items-baseline justify-between mt-1">
                  <span className="font-mono text-base font-extrabold">
                    {data.count}
                  </span>
                  {isActive && (
                    <span className="text-[10px] font-mono font-bold">
                      {data.maxScore.toFixed(0)} pts
                    </span>
                  )}
                </div>
              </div>

              {/* Mini Techniques list inside card */}
              {isActive && (
                <div className="mt-2 pt-1.5 border-t border-current/10 space-y-1">
                  {Array.from(data.techniques.entries()).map(([techId, tech]) => (
                    <div
                      key={techId}
                      className="text-[9px] font-mono truncate px-1 py-0.5 rounded bg-black/5 dark:bg-white/5 flex items-center justify-between"
                      title={`${techId} - ${tech.name} (${tech.count} events)`}
                    >
                      <span className="font-bold">{techId}</span>
                      <span className="opacity-80">x{tech.count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Expanded Tactic Techniques Details Panel */}
      {selectedTactic && tacticMap[selectedTactic] && tacticMap[selectedTactic].count > 0 && (
        <div className="mt-3 p-3 bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800 rounded-lg animate-in fade-in text-xs">
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-zinc-800 dark:text-zinc-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-500" />
              Observed Techniques under tactic: {selectedTactic}
            </span>
            <button
              onClick={() => setSelectedTactic(null)}
              className="text-[10px] text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-300"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
            {Array.from(tacticMap[selectedTactic].techniques.entries()).map(([techId, tech]) => (
              <div
                key={techId}
                className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded p-2.5 flex items-start justify-between gap-2 shadow-sm"
              >
                <div>
                  <div className="font-mono font-bold text-blue-600 dark:text-blue-400">
                    {techId}
                  </div>
                  <div className="text-[11px] font-medium text-zinc-800 dark:text-zinc-200 mt-0.5">
                    {tech.name}
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                    {tech.count} hit{tech.count > 1 ? 's' : ''}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
