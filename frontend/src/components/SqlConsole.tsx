'use client';

import React, { useState } from 'react';
import { executeSQLConsole } from '@/lib/pglite';
import { Terminal, Play, Database, Check, AlertCircle } from 'lucide-react';

interface SqlConsoleProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SqlConsole: React.FC<SqlConsoleProps> = ({ isOpen, onClose }) => {
  const [sql, setSql] = useState(
    `SELECT alert_uuid, source, event_type, calculated_score, status FROM alerts ORDER BY calculated_score DESC LIMIT 10;`
  );
  const [result, setResult] = useState<{ rows: any[]; fields: string[]; durationMs: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);

  if (!isOpen) return null;

  const handleRunSQL = async () => {
    setExecuting(true);
    setError(null);
    try {
      const res = await executeSQLConsole(sql);
      setResult(res);
    } catch (err: any) {
      setError(err?.message || 'SQL execution failed');
      setResult(null);
    } finally {
      setExecuting(false);
    }
  };

  const sampleQueries = [
    {
      label: 'All Alerts By Threat Score',
      query: `SELECT alert_uuid, source, calculated_score, status FROM alerts ORDER BY calculated_score DESC;`,
    },
    {
      label: 'Enriched IOCs Breakdown',
      query: `SELECT a.alert_uuid, a.source, i.ioc_type, i.ioc_value, a.calculated_score FROM alerts a JOIN alert_iocs i ON a.alert_uuid = i.alert_uuid;`,
    },
    {
      label: 'Enrichment CTI Provider Stats',
      query: `SELECT provider, COUNT(*) as hit_count, ROUND(AVG(normalized_score), 2) as avg_score FROM enrichment_data GROUP BY provider;`,
    },
    {
      label: 'Triage Audit Logs',
      query: `SELECT * FROM triage_actions ORDER BY performed_at DESC;`,
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-blue-900/50 rounded-lg text-blue-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                PGlite Browser-WASM SQL Console
                <span className="text-[10px] font-mono bg-blue-950 text-blue-300 border border-blue-800 px-2 py-0.5 rounded-full">
                  PostgreSQL in WebAssembly
                </span>
              </h3>
              <p className="text-xs text-zinc-400">
                Execute client-side SQL queries directly against your local browser database with sub-millisecond latency.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-white px-2.5 py-1 rounded-lg bg-zinc-800/80 hover:bg-zinc-800 text-xs transition"
          >
            ✕ Close
          </button>
        </div>

        {/* Query Input Section */}
        <div className="p-6 border-b border-zinc-800 space-y-3">
          <div className="flex flex-wrap gap-2">
            <span className="text-xs text-zinc-400 font-medium self-center">Templates:</span>
            {sampleQueries.map((sq, i) => (
              <button
                key={i}
                onClick={() => setSql(sq.query)}
                className="text-[11px] bg-zinc-900 hover:bg-zinc-800 border border-zinc-700/80 px-2.5 py-1 rounded text-zinc-300 transition"
              >
                {sq.label}
              </button>
            ))}
          </div>

          <div className="relative">
            <textarea
              value={sql}
              onChange={(e) => setSql(e.target.value)}
              rows={4}
              className="w-full bg-zinc-900/90 border border-zinc-700/80 rounded-xl p-3 font-mono text-xs text-emerald-400 focus:outline-none focus:border-blue-500 shadow-inner"
              placeholder="SELECT * FROM alerts;"
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="text-xs text-zinc-500 font-mono flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5" />
              Target: idb://soc-alerts-db (IndexedDB / WASM Engine)
            </div>
            <button
              onClick={handleRunSQL}
              disabled={executing}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow transition disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {executing ? 'Executing SQL...' : 'Run Query'}
            </button>
          </div>
        </div>

        {/* Results Section */}
        <div className="p-6 flex-1 overflow-auto bg-zinc-950/60 font-mono text-xs">
          {error && (
            <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 rounded-lg flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">PostgreSQL Syntax Error:</span> {error}
              </div>
            </div>
          )}

          {result && (
            <div>
              <div className="flex items-center justify-between mb-2 text-zinc-400 text-[11px]">
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <Check className="w-3.5 h-3.5" />
                  Query returned {result.rows.length} rows
                </span>
                <span>Latency: {result.durationMs}ms</span>
              </div>

              {result.rows.length === 0 ? (
                <div className="p-4 text-zinc-500 text-center">Empty query result set</div>
              ) : (
                <div className="overflow-x-auto border border-zinc-800 rounded-lg">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-zinc-900 border-b border-zinc-800">
                        {result.fields.map((f, i) => (
                          <th key={i} className="px-3 py-2 text-zinc-300 font-semibold text-[11px]">
                            {f}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60">
                      {result.rows.map((row, rIdx) => (
                        <tr key={rIdx} className="hover:bg-zinc-900/50">
                          {result.fields.map((f, fIdx) => (
                            <td key={fIdx} className="px-3 py-1.5 text-zinc-300 max-w-xs truncate text-[11px]">
                              {typeof row[f] === 'object'
                                ? JSON.stringify(row[f])
                                : String(row[f] ?? 'NULL')}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {!result && !error && (
            <div className="text-center py-8 text-zinc-500 text-xs">
              Click &quot;Run Query&quot; to execute SQL in your browser-native PostgreSQL WASM database.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
