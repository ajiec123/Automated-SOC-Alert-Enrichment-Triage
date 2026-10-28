'use client';

import React, { useState } from 'react';
import { AlertRecord, IncidentGroup, DashboardMetrics, TriageAuditLog } from '@/types/alert';
import { generateExecutiveMarkdownReport } from '@/lib/report';
import {
  FileText,
  Printer,
  Download,
  Copy,
  Check,
  ShieldCheck,
  Flame,
  Layers,
  Clock,
  User,
  Crosshair,
  AlertTriangle,
} from 'lucide-react';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  alerts: AlertRecord[];
  incidents: IncidentGroup[];
  metrics: DashboardMetrics;
  auditLogs: TriageAuditLog[];
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  alerts,
  incidents,
  metrics,
  auditLogs,
}) => {
  const [shiftName, setShiftName] = useState('SOC Operational Shift 01 (Day)');
  const [leadAnalyst, setLeadAnalyst] = useState('SOC Web Analyst / IR Lead');
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<'PREVIEW' | 'RAW'>('PREVIEW');

  if (!isOpen) return null;

  const markdownContent = generateExecutiveMarkdownReport(alerts, incidents, metrics, auditLogs, {
    shiftName,
    leadAnalyst,
  });

  const handleCopyMarkdown = async () => {
    try {
      await navigator.clipboard.writeText(markdownContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch (e) {
      console.error('Failed to copy to clipboard', e);
    }
  };

  const handleDownloadMarkdown = () => {
    const blob = new Blob([markdownContent], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `SOC_Shift_Report_${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/60 dark:bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-2xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Top Header */}
        <div className="px-6 py-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between bg-zinc-50 dark:bg-zinc-900/60 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 text-blue-600 dark:bg-blue-950/80 dark:text-blue-400 rounded-xl">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-zinc-900 dark:text-white flex items-center gap-2">
                Executive Incident &amp; Shift Handover Report
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300 border border-blue-200 dark:border-blue-800">
                  TLP:AMBER
                </span>
              </h3>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                Auto-generated executive investigation brief with Root Cause Analysis, MITRE ATT&amp;CK correlations &amp; PGlite audit trails.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white px-2.5 py-1.5 rounded-lg bg-zinc-200/60 hover:bg-zinc-200 dark:bg-zinc-800/80 dark:hover:bg-zinc-800 text-xs transition"
            >
              ✕ Close
            </button>
          </div>
        </div>

        {/* Action Controls & Report Settings Bar */}
        <div className="px-6 py-3 bg-white dark:bg-zinc-900/40 border-b border-zinc-200 dark:border-zinc-800 flex flex-wrap items-center justify-between gap-3 text-xs shrink-0">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="text-zinc-500 dark:text-zinc-400 font-medium">Shift:</span>
              <input
                type="text"
                value={shiftName}
                onChange={(e) => setShiftName(e.target.value)}
                className="bg-slate-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 px-2 py-1 rounded text-xs text-zinc-800 dark:text-zinc-200 w-48 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-zinc-500 dark:text-zinc-400 font-medium">Lead:</span>
              <input
                type="text"
                value={leadAnalyst}
                onChange={(e) => setLeadAnalyst(e.target.value)}
                className="bg-slate-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 px-2 py-1 rounded text-xs text-zinc-800 dark:text-zinc-200 w-48 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {/* Export & View Mode Buttons */}
          <div className="flex items-center gap-2">
            <div className="flex items-center p-0.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-900">
              <button
                onClick={() => setViewMode('PREVIEW')}
                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition ${
                  viewMode === 'PREVIEW'
                    ? 'bg-white dark:bg-zinc-800 text-blue-600 dark:text-blue-400 shadow-2xs'
                    : 'text-zinc-600 dark:text-zinc-400'
                }`}
              >
                Executive Preview
              </button>
              <button
                onClick={() => setViewMode('RAW')}
                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition ${
                  viewMode === 'RAW'
                    ? 'bg-white dark:bg-zinc-800 text-blue-600 dark:text-blue-400 shadow-2xs'
                    : 'text-zinc-600 dark:text-zinc-400'
                }`}
              >
                Markdown Source
              </button>
            </div>

            <button
              onClick={handleCopyMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-zinc-800 dark:text-zinc-200 border border-zinc-200 dark:border-zinc-700 rounded-lg text-xs font-medium transition shadow-2xs"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied!' : 'Copy Markdown'}
            </button>

            <button
              onClick={handleDownloadMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow transition"
            >
              <Download className="w-3.5 h-3.5" />
              Download .MD
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-white rounded-lg text-xs font-semibold shadow transition dark:bg-zinc-700 dark:hover:bg-zinc-600"
            >
              <Printer className="w-3.5 h-3.5" />
              Print / Save PDF
            </button>
          </div>
        </div>

        {/* Report Content Body */}
        <div className="flex-1 overflow-y-auto p-6 bg-slate-50 dark:bg-zinc-950 font-sans text-xs">
          {viewMode === 'RAW' ? (
            <div className="relative">
              <textarea
                readOnly
                value={markdownContent}
                rows={24}
                className="w-full bg-slate-900 text-emerald-400 border border-zinc-700/80 rounded-xl p-4 font-mono text-xs focus:outline-none shadow-inner"
              />
            </div>
          ) : (
            /* Styled Executive Printable Document Layout */
            <div className="max-w-4xl mx-auto bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl p-8 shadow-sm space-y-6 text-zinc-800 dark:text-zinc-200 print:border-none print:shadow-none print:p-0">
              {/* Document Header */}
              <div className="border-b-2 border-zinc-800 dark:border-zinc-200 pb-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                  <div className="text-[10px] font-mono uppercase font-bold tracking-widest text-red-600 dark:text-red-400">
                    TLP:AMBER &bull; STRICTLY CONFIDENTIAL &bull; FOR INTERNAL SOC USE ONLY
                  </div>
                  <h1 className="text-xl font-black text-zinc-900 dark:text-white mt-1">
                    EXECUTIVE SECURITY INCIDENT &amp; SHIFT HANDOVER REPORT
                  </h1>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                    Automated SOC Alert Enrichment &amp; Triage Platform
                  </p>
                </div>
                <div className="text-right text-xs space-y-0.5 font-mono">
                  <div>
                    <span className="text-zinc-500">Date:</span> {new Date().toLocaleDateString()}
                  </div>
                  <div>
                    <span className="text-zinc-500">Shift:</span> <strong>{shiftName}</strong>
                  </div>
                  <div>
                    <span className="text-zinc-500">Lead:</span> <strong>{leadAnalyst}</strong>
                  </div>
                </div>
              </div>

              {/* Section 1: Executive KPI Cards */}
              <div>
                <h2 className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300 border-b border-zinc-200 dark:border-zinc-800 pb-1 mb-3">
                  1. Operational Summary &amp; Key Risk Indicators
                </h2>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800 rounded-lg">
                    <div className="text-[10px] uppercase text-zinc-500">Total Alerts Processed</div>
                    <div className="text-xl font-bold font-mono text-zinc-900 dark:text-white">
                      {metrics.totalAlerts}
                    </div>
                  </div>
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800 rounded-lg">
                    <div className="text-[10px] uppercase text-red-600 dark:text-red-400">Critical Threats (≥80)</div>
                    <div className="text-xl font-bold font-mono text-red-600 dark:text-red-400">
                      {metrics.criticalCount}
                    </div>
                  </div>
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800 rounded-lg">
                    <div className="text-[10px] uppercase text-purple-600 dark:text-purple-400">Mitigated / Contained</div>
                    <div className="text-xl font-bold font-mono text-purple-700 dark:text-purple-300">
                      {metrics.containedCount}
                    </div>
                  </div>
                  <div className="p-3 bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800 rounded-lg">
                    <div className="text-[10px] uppercase text-zinc-500">Correlated Campaigns</div>
                    <div className="text-xl font-bold font-mono text-blue-600 dark:text-blue-400">
                      {incidents.length}
                    </div>
                  </div>
                </div>
              </div>

              {/* Section 2: Correlated Incidents Table */}
              <div>
                <h2 className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300 border-b border-zinc-200 dark:border-zinc-800 pb-1 mb-3">
                  2. Correlated Multi-Stage Adversary Campaigns
                </h2>
                <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-lg">
                  <table className="w-full text-left border-collapse text-[11px]">
                    <thead>
                      <tr className="bg-zinc-100 dark:bg-zinc-900 border-b border-zinc-200 dark:border-zinc-800 font-semibold">
                        <th className="p-2.5">Incident ID</th>
                        <th className="p-2.5">Target Entity</th>
                        <th className="p-2.5">Threat Score</th>
                        <th className="p-2.5">MITRE Kill-Chain Progression</th>
                        <th className="p-2.5">Stages</th>
                        <th className="p-2.5">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
                      {incidents.map((inc) => (
                        <tr key={inc.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-950">
                          <td className="p-2.5 font-mono font-bold text-blue-600 dark:text-blue-400">
                            {inc.id}
                          </td>
                          <td className="p-2.5 font-mono">{inc.keyEntity}</td>
                          <td className="p-2.5 font-mono font-bold">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] ${
                                inc.highestScore >= 80
                                  ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                                  : 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300'
                              }`}
                            >
                              {inc.highestScore.toFixed(0)}/100 [{inc.highestTier}]
                            </span>
                          </td>
                          <td className="p-2.5">{inc.mitreTactics.join(' → ')}</td>
                          <td className="p-2.5 font-mono">{inc.alerts.length} events</td>
                          <td className="p-2.5">
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                              {inc.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Section 3: Root Cause & Hypotheses Analysis */}
              <div>
                <h2 className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300 border-b border-zinc-200 dark:border-zinc-800 pb-1 mb-3">
                  3. Forensic Root Cause, Hypotheses &amp; Remediation Verdicts
                </h2>
                <div className="space-y-3">
                  {alerts.map((a) => {
                    return (
                      <div
                        key={a.alert_uuid}
                        className="p-3 bg-zinc-50 dark:bg-zinc-950/60 border border-zinc-200 dark:border-zinc-800 rounded-lg space-y-2 text-[11px]"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-blue-600 dark:text-blue-400">
                              {a.alert_uuid}
                            </span>
                            <span className="font-semibold text-zinc-900 dark:text-white">
                              {a.event_type}
                            </span>
                          </div>
                          <span className="px-2 py-0.5 rounded bg-zinc-200 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200 font-mono text-[10px]">
                            Score: {a.calculated_score.toFixed(1)}/100 &bull; {a.status}
                          </span>
                        </div>

                        <div className="text-zinc-600 dark:text-zinc-400">
                          <strong>Root Cause Summary:</strong>{' '}
                          {a.root_cause?.summary ||
                            'Telemetry matched signature thresholds. Multi-CTI reputation corroborated.'}
                        </div>

                        {a.root_cause?.whatWouldSettleIt && (
                          <div className="text-zinc-700 dark:text-zinc-300">
                            <strong>Verification Test:</strong> {a.root_cause.whatWouldSettleIt}
                          </div>
                        )}

                        <div className="text-blue-700 dark:text-blue-400">
                          <strong>Remediation Verdict:</strong>{' '}
                          {a.auto_action_taken || a.remediation_notes || 'Manual Analyst Action Required'}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Section 4: Audit Logs */}
              {auditLogs.length > 0 && (
                <div>
                  <h2 className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300 border-b border-zinc-200 dark:border-zinc-800 pb-1 mb-2">
                    4. PGlite WASM Triage Audit Trail
                  </h2>
                  <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-lg">
                    <table className="w-full text-left border-collapse text-[10px]">
                      <thead>
                        <tr className="bg-zinc-100 dark:bg-zinc-900 border-b border-zinc-200 dark:border-zinc-800">
                          <th className="p-2">Timestamp (UTC)</th>
                          <th className="p-2">Alert UUID</th>
                          <th className="p-2">Actor</th>
                          <th className="p-2">Action</th>
                          <th className="p-2">Analyst Notes &amp; Target Hypothesis</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
                        {auditLogs.slice(0, 10).map((log, idx) => (
                          <tr key={idx}>
                            <td className="p-2 font-mono text-zinc-500">
                              {new Date(log.performed_at).toLocaleTimeString()}
                            </td>
                            <td className="p-2 font-mono font-bold text-blue-600 dark:text-blue-400">
                              {log.alert_uuid}
                            </td>
                            <td className="p-2">{log.actor}</td>
                            <td className="p-2 font-bold uppercase">{log.action_taken}</td>
                            <td className="p-2 truncate max-w-xs">{log.notes || 'N/A'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Sign-off Footer */}
              <div className="pt-4 border-t border-zinc-300 dark:border-zinc-700 flex justify-between items-end text-xs">
                <div>
                  <div className="font-bold text-zinc-900 dark:text-white">Outgoing Shift Lead Sign-off:</div>
                  <div className="text-zinc-500 mt-1">Signature: __________________________</div>
                </div>
                <div className="text-right text-[10px] text-zinc-400">
                  Automated SOC Engine v1.0 &bull; PGlite WASM &bull; TLP:AMBER
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
