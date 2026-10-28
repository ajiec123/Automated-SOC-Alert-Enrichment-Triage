'use client';

import React, { useState, useMemo } from 'react';
import { AlertRecord, AlertStatus, HypothesisItem } from '@/types/alert';
import { recordTriageInPGlite } from '@/lib/pglite';
import { generateRootCauseAnalysis } from '@/lib/hypothesis';
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
  ChevronDown,
  ChevronUp,
  HelpCircle,
  Check,
  MinusCircle,
  Lightbulb,
  Crosshair,
  Wrench,
  FileText,
  AlertCircle,
} from 'lucide-react';

interface AlertCardProps {
  alert: AlertRecord;
  onActionComplete?: () => void;
}

export const AlertCard: React.FC<AlertCardProps> = ({ alert, onActionComplete }) => {
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [isRCAOpen, setIsRCAOpen] = useState<boolean>(true); // default open or expanded
  const [selectedHypothesisId, setSelectedHypothesisId] = useState<string>('');
  const [analystNotes, setAnalystNotes] = useState<string>('');
  const [showNotesInput, setShowNotesInput] = useState<boolean>(false);

  // Generate deterministic Root Cause & Hypotheses based on alert attributes
  const rca = useMemo(() => {
    return alert.root_cause || generateRootCauseAnalysis(alert);
  }, [alert]);

  // Set default selected hypothesis if not selected yet
  const effectiveSelectedHypothesis = useMemo(() => {
    if (selectedHypothesisId) return selectedHypothesisId;
    // Default to the first 'still_open' hypothesis, or first item
    const firstOpen = rca.hypotheses.find((h) => h.status === 'still_open');
    return firstOpen ? firstOpen.id : rca.hypotheses[0]?.id || '';
  }, [selectedHypothesisId, rca]);

  const activeHypothesis = useMemo(() => {
    return rca.hypotheses.find((h) => h.id === effectiveSelectedHypothesis);
  }, [rca, effectiveSelectedHypothesis]);

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

    const selectedTitle = activeHypothesis ? activeHypothesis.title : effectiveSelectedHypothesis;
    const finalNotes = analystNotes.trim()
      ? `${analystNotes.trim()} | Hypothesis: [${selectedTitle}]`
      : `Verdict applied under hypothesis: [${selectedTitle}]`;

    try {
      // 1. Notify Backend API
      await fetch(backendUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_uuid: alert.alert_uuid,
          action,
          actor: 'SOC Web Analyst',
          notes: finalNotes,
          hypothesis_selected: effectiveSelectedHypothesis,
        }),
      }).catch((e) => console.warn('Backend triage call failed, updating local PGlite:', e));

      // 2. Update local PGlite WASM
      await recordTriageInPGlite(
        alert.alert_uuid,
        'SOC Web Analyst',
        action,
        targetStatus,
        finalNotes,
        effectiveSelectedHypothesis
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
      className={`border rounded-xl p-5 mb-5 shadow-sm transition-all duration-200 hover:shadow-md ${getTierColor(
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
        <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          {alert.enrichments.map((enr, i) => (
            <div
              key={i}
              className="bg-white/80 dark:bg-zinc-900/80 border border-zinc-200 dark:border-zinc-800 rounded-lg p-2.5 text-xs shadow-sm"
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

      {/* Auto-Mitigation Notice */}
      {alert.auto_action_taken && (
        <div className="mt-3 text-xs bg-white/70 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded p-2 text-zinc-700 dark:text-zinc-300 flex items-center gap-2 shadow-sm">
          <Activity className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400 shrink-0" />
          <span>{alert.auto_action_taken}</span>
        </div>
      )}

      {/* ========================================================================= */}
      {/* ROOT CAUSE ANALYSIS & WHAT TO DO (Collapsible Section modeled after user UI) */}
      {/* ========================================================================= */}
      <div className="mt-4 bg-white dark:bg-zinc-900/90 border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden shadow-sm">
        {/* RCA Accordion Header */}
        <button
          onClick={() => setIsRCAOpen((prev) => !prev)}
          type="button"
          className="w-full flex items-center justify-between px-4 py-3 bg-zinc-50/80 hover:bg-zinc-100/80 dark:bg-zinc-900/70 dark:hover:bg-zinc-800/60 border-b border-zinc-200 dark:border-zinc-800 text-left transition"
        >
          <div className="flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
            <span className="text-xs uppercase font-extrabold tracking-wider text-zinc-800 dark:text-zinc-200">
              Root Cause &amp; Hypothesis Analysis
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300 border border-blue-200 dark:border-blue-800 font-mono">
              {rca.hypotheses.length} Hypotheses Evaluated
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
            <span>{isRCAOpen ? 'Collapse' : 'Expand Details'}</span>
            {isRCAOpen ? (
              <ChevronUp className="w-4 h-4 text-zinc-500" />
            ) : (
              <ChevronDown className="w-4 h-4 text-zinc-500" />
            )}
          </div>
        </button>

        {isRCAOpen && (
          <div className="p-4 space-y-4 text-xs">
            {/* Box 1: CAUSE / Summary & Hypotheses List */}
            <div className="border border-zinc-200 dark:border-zinc-800 rounded-lg p-3.5 bg-slate-50/50 dark:bg-zinc-950/40 space-y-3">
              {/* Header: CAUSE */}
              <div>
                <div className="flex items-center gap-1.5 text-zinc-800 dark:text-zinc-200 font-bold uppercase tracking-wider text-[11px] mb-1">
                  <FileText className="w-3.5 h-3.5 text-zinc-500" />
                  CAUSE
                </div>
                <p className="text-zinc-600 dark:text-zinc-300 leading-relaxed text-xs">
                  {rca.summary}
                </p>
              </div>

              {/* OTHER HYPOTHESES, STILL OPEN */}
              <div className="pt-2 border-t border-zinc-200/70 dark:border-zinc-800/70">
                <div className="text-[10px] uppercase font-bold tracking-wider text-zinc-500 dark:text-zinc-400 mb-2">
                  Hypotheses Status &amp; Evidence
                </div>

                <div className="space-y-2">
                  {rca.hypotheses.map((h: HypothesisItem) => {
                    const isSelected = effectiveSelectedHypothesis === h.id;
                    return (
                      <div
                        key={h.id}
                        onClick={() => setSelectedHypothesisId(h.id)}
                        className={`cursor-pointer border rounded-lg p-2.5 transition flex items-start gap-2.5 ${
                          isSelected
                            ? 'bg-blue-50/80 border-blue-400 dark:bg-blue-950/40 dark:border-blue-600 shadow-sm'
                            : 'bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800 hover:border-zinc-300 dark:hover:border-zinc-700'
                        }`}
                      >
                        {/* Status Icon */}
                        <div className="mt-0.5 shrink-0">
                          {h.status === 'confirmed' ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                          ) : h.status === 'refuted' ? (
                            <XCircle className="w-4 h-4 text-zinc-400 dark:text-zinc-600" />
                          ) : h.status === 'not_confirmed' ? (
                            <MinusCircle className="w-4 h-4 text-zinc-400" />
                          ) : (
                            <HelpCircle className="w-4 h-4 text-amber-500" />
                          )}
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center justify-between gap-1 mb-0.5">
                            <span
                              className={`font-semibold text-xs ${
                                isSelected
                                  ? 'text-blue-900 dark:text-blue-200'
                                  : 'text-zinc-800 dark:text-zinc-200'
                              }`}
                            >
                              {h.title}
                            </span>
                            <span
                              className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded ${
                                h.status === 'confirmed'
                                  ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                                  : h.status === 'still_open'
                                  ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                                  : h.status === 'refuted'
                                  ? 'bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-400'
                                  : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800/60 dark:text-zinc-400'
                              }`}
                            >
                              {h.status.replace('_', ' ')}
                            </span>
                          </div>

                          <p className="text-[11px] text-zinc-600 dark:text-zinc-400 leading-normal">
                            {h.description}
                          </p>

                          {/* Evidence rows if present */}
                          {(h.evidenceSupport || h.evidenceContradict) && (
                            <div className="mt-1.5 pt-1 border-t border-zinc-200/60 dark:border-zinc-800/60 text-[10px] space-y-0.5">
                              {h.evidenceSupport && (
                                <div className="text-emerald-700 dark:text-emerald-400 flex items-start gap-1">
                                  <span className="font-semibold">Supporting:</span>
                                  <span>{h.evidenceSupport}</span>
                                </div>
                              )}
                              {h.evidenceContradict && (
                                <div className="text-zinc-500 dark:text-zinc-400 flex items-start gap-1">
                                  <span className="font-semibold">Contradicting:</span>
                                  <span>{h.evidenceContradict}</span>
                                </div>
                              )}
                            </div>
                          )}
                        </div>

                        {/* Selection Radio Indicator */}
                        <div className="shrink-0 self-center pl-1">
                          <span
                            className={`w-3.5 h-3.5 rounded-full border flex items-center justify-center ${
                              isSelected
                                ? 'border-blue-600 bg-blue-600 text-white'
                                : 'border-zinc-300 dark:border-zinc-700'
                            }`}
                          >
                            {isSelected && <Check className="w-2.5 h-2.5" />}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* WHAT WOULD SETTLE IT */}
              {rca.whatWouldSettleIt && (
                <div className="pt-2 border-t border-zinc-200/70 dark:border-zinc-800/70 flex items-start gap-2">
                  <Lightbulb className="w-3.5 h-3.5 text-amber-500 shrink-0 mt-0.5" />
                  <div>
                    <span className="text-[10px] uppercase font-bold tracking-wider text-zinc-500 dark:text-zinc-400 mr-1.5">
                      WHAT WOULD SETTLE IT:
                    </span>
                    <span className="text-zinc-700 dark:text-zinc-300 text-xs">
                      {rca.whatWouldSettleIt}
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Box 2: WHAT TO DO (Recommended next actions) */}
            <div className="border border-blue-200 dark:border-blue-900/50 bg-blue-50/40 dark:bg-blue-950/20 rounded-lg p-3.5 space-y-2">
              <div className="flex items-center gap-1.5 text-blue-900 dark:text-blue-300 font-bold uppercase tracking-wider text-[11px]">
                <Wrench className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                WHAT TO DO
              </div>
              <div className="text-xs text-zinc-800 dark:text-zinc-200 font-medium">
                {rca.whatToDo.nextCheck}
              </div>
              <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
                {rca.whatToDo.description}
              </p>
            </div>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* ENHANCED REMEDIATION VERDICT BAR (Structured with Hypothesis Selection)   */}
      {/* ========================================================================= */}
      <div className="mt-4 pt-3.5 border-t border-zinc-200/80 dark:border-zinc-800/80 space-y-3">
        {/* Hypothesis Selection Dropdown & Analyst Notes Trigger */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2 flex-1">
            <label className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 shrink-0 flex items-center gap-1">
              <Crosshair className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              Remediation Target Hypothesis:
            </label>
            <select
              value={effectiveSelectedHypothesis}
              onChange={(e) => setSelectedHypothesisId(e.target.value)}
              className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded-lg px-2.5 py-1 text-xs text-zinc-800 dark:text-zinc-200 focus:outline-none focus:border-blue-500 flex-1 truncate"
            >
              {rca.hypotheses.map((h) => (
                <option key={h.id} value={h.id}>
                  [{h.status.toUpperCase()}] {h.title}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => setShowNotesInput((prev) => !prev)}
            type="button"
            className="text-[11px] text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1 shrink-0 self-end sm:self-center"
          >
            <FileText className="w-3 h-3" />
            {showNotesInput ? 'Hide Notes' : '+ Add Remediation Notes'}
          </button>
        </div>

        {/* Optional Notes Input Area */}
        {showNotesInput && (
          <div className="animate-in fade-in">
            <textarea
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Provide justification, ticketing reference, or investigation remarks before applying remediation..."
              rows={2}
              className="w-full bg-slate-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg p-2 text-xs text-zinc-800 dark:text-zinc-200 placeholder-zinc-400 focus:outline-none focus:border-blue-500"
            />
          </div>
        )}

        {/* Action Execution Buttons */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
          <div className="text-[11px] text-zinc-500 dark:text-zinc-400 flex items-center gap-1">
            <AlertCircle className="w-3.5 h-3.5 text-amber-500" />
            <span>Select action to commit verdict to SIEM &amp; PGlite WASM:</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* 1. Block IP */}
            <button
              onClick={() => handleAction('block_ip')}
              disabled={loadingAction !== null || alert.status === 'CONTAINED'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white transition disabled:opacity-50 shadow-sm"
              title="Apply perimeter firewall edge drop to active IOC IP"
            >
              <Ban className="w-3.5 h-3.5" />
              {loadingAction === 'block_ip' ? 'Applying...' : '🚫 Block IP'}
            </button>

            {/* 2. Isolate Host */}
            <button
              onClick={() => handleAction('isolate_host')}
              disabled={loadingAction !== null || alert.status === 'CONTAINED'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-purple-700 hover:bg-purple-600 text-white transition disabled:opacity-50 shadow-sm"
              title="Sever endpoint network adapter via EDR to halt lateral spread"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              {loadingAction === 'isolate_host' ? 'Isolating...' : '🛡️ Isolate Host'}
            </button>

            {/* 3. Mark Triaged */}
            <button
              onClick={() => handleAction('resolve')}
              disabled={loadingAction !== null || alert.status === 'TRIAGED'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition disabled:opacity-50 shadow-sm"
              title="Confirm hypothesis and record remediation as completed"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              {loadingAction === 'resolve' ? 'Updating...' : '✅ Mark Triaged'}
            </button>

            {/* 4. Dismiss */}
            <button
              onClick={() => handleAction('dismiss')}
              disabled={loadingAction !== null || alert.status === 'DISMISSED'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-200 hover:bg-zinc-300 text-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 dark:text-zinc-300 transition disabled:opacity-50 shadow-sm"
              title="Refute hypothesis / dismiss alert as benign false-positive"
            >
              <XCircle className="w-3.5 h-3.5" />
              {loadingAction === 'dismiss' ? 'Dismissing...' : '❌ Dismiss'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
