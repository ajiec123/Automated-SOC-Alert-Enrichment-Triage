'use client';

import React, { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { AlertRecord, AlertStatus, DashboardMetrics, IncidentGroup } from '@/types/alert';
import { fetchAlertsFromPGlite, fetchDashboardMetrics } from '@/lib/pglite';
import { useAlertWebSocket } from '@/lib/websocket';
import { AlertCard } from '@/components/AlertCard';
import { ThreatChart } from '@/components/ThreatChart';
import { SqlConsole } from '@/components/SqlConsole';
import { SimulationModal } from '@/components/SimulationModal';
import { ThemeToggle } from '@/components/ThemeToggle';
import { MitreHeatmap } from '@/components/MitreHeatmap';
import { IncidentStoryline } from '@/components/IncidentStoryline';
import { correlateAlertsIntoIncidents } from '@/lib/mitre';
import {
  ShieldAlert,
  Database,
  Radio,
  Zap,
  RefreshCw,
  Search,
  Filter,
  CheckCircle,
  AlertTriangle,
  Server,
  Layers,
  AlertOctagon,
  Flame,
  LayoutGrid,
  Crosshair,
} from 'lucide-react';

export default function SOCDashboard() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [metrics, setMetrics] = useState<DashboardMetrics>({
    totalAlerts: 0,
    criticalCount: 0,
    highCount: 0,
    containedCount: 0,
    avgScore: 0,
  });
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'INCIDENTS' | 'ALERTS' | 'MITRE'>('INCIDENTS');
  const [isSqlConsoleOpen, setIsSqlConsoleOpen] = useState(false);
  const [isSimModalOpen, setIsSimModalOpen] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [initError, setInitError] = useState<string | null>(null);

  const isInitialLoad = useRef(true);

  // Load alerts and metrics directly from browser-native PGlite WASM
  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const data = await fetchAlertsFromPGlite(statusFilter);
      const m = await fetchDashboardMetrics();
      setAlerts(data);
      setMetrics(m);
      setInitError(null);
    } catch (err: any) {
      console.error('Error querying PGlite database:', err);
      if (isInitialLoad.current) {
        setInitError(err?.message || 'Database initialization error');
      }
    } finally {
      setIsRefreshing(false);
      isInitialLoad.current = false;
      setMounted(true);
    }
  }, [statusFilter]);

  // Connect WebSocket to Go backend - on any stream event, re-query PGlite
  const { status: socketStatus } = useAlertWebSocket(() => {
    loadData();
  });

  useEffect(() => {
    // Safety fallback: if initialization takes more than 6 seconds, force unblock the UI
    const timer = setTimeout(() => {
      setMounted((prev) => {
        if (!prev) {
          console.warn('[SOC Dashboard] Fallback timeout triggered: unblocking splash screen');
          return true;
        }
        return prev;
      });
    }, 6000);

    loadData();

    return () => clearTimeout(timer);
  }, [loadData]);

  // Correlate alerts into multi-stage attack campaigns / incidents
  const incidents: IncidentGroup[] = useMemo(() => {
    return correlateAlertsIntoIncidents(alerts);
  }, [alerts]);

  // Filter alerts by search query
  const filteredAlerts = alerts.filter((a) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    const matchesEvent = a.event_type.toLowerCase().includes(q);
    const matchesSource = a.source.toLowerCase().includes(q);
    const matchesUUID = a.alert_uuid.toLowerCase().includes(q);
    const matchesIOC = a.iocs?.some(
      (ioc) =>
        ioc.ioc_value.toLowerCase().includes(q) ||
        ioc.ioc_type.toLowerCase().includes(q)
    );
    return matchesEvent || matchesSource || matchesUUID || matchesIOC;
  });

  // Filter incidents by search query
  const filteredIncidents = incidents.filter((inc) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    const matchesTitle = inc.title.toLowerCase().includes(q);
    const matchesEntity = inc.keyEntity.toLowerCase().includes(q);
    const matchesTactic = inc.mitreTactics.some((t) => t.toLowerCase().includes(q));
    const matchesAlerts = inc.alerts.some(
      (a) =>
        a.event_type.toLowerCase().includes(q) ||
        a.alert_uuid.toLowerCase().includes(q)
    );
    return matchesTitle || matchesEntity || matchesTactic || matchesAlerts;
  });

  if (!mounted) {
    return (
      <div className="flex flex-col h-screen items-center justify-center bg-slate-50 dark:bg-zinc-950 text-zinc-600 dark:text-zinc-400 font-mono text-sm p-4">
        <div className="flex items-center gap-3">
          <Database className="w-5 h-5 text-blue-500 animate-spin" />
          <span>Initializing Browser-WASM PGlite PostgreSQL Engine...</span>
        </div>
        <p className="text-xs text-zinc-400 dark:text-zinc-500 mt-2 text-center max-w-sm">
          Preparing client-side WebAssembly PostgreSQL engine &amp; IndexedDB storage.
        </p>
      </div>
    );
  }

  return (
    <main className="min-h-screen p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto transition-colors duration-200">
      {/* Top Header */}
      <header className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-zinc-200 dark:border-zinc-800">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-blue-600/10 dark:bg-blue-600/20 border border-blue-500/20 dark:border-blue-500/30 rounded-xl text-blue-600 dark:text-blue-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-black tracking-tight text-zinc-900 dark:text-white flex items-center gap-2">
                Automated SOC Alert Triage Platform
                <span className="text-xs font-mono font-semibold bg-zinc-100 text-zinc-700 border-zinc-200 dark:bg-zinc-800 dark:border-zinc-700 border px-2 py-0.5 rounded dark:text-zinc-300">
                  SIEM &bull; SOAR
                </span>
              </h1>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                MITRE ATT&amp;CK Correlation &bull; Multi-Stage Attack Storylines &bull; Browser-Native PGlite PostgreSQL Engine
              </p>
            </div>
          </div>
        </div>

        {/* Engine Status Indicators & Action Bar */}
        <div className="flex flex-wrap items-center gap-2.5 self-stretch md:self-auto justify-end">
          {/* Theme Toggle Button */}
          <ThemeToggle />

          {/* WebSocket Status */}
          <div className="flex items-center gap-2 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 px-3 py-1.5 rounded-lg text-xs font-mono shadow-sm">
            <span
              className={`w-2 h-2 rounded-full ${
                socketStatus === 'connected'
                  ? 'bg-emerald-500 animate-pulse'
                  : 'bg-zinc-400 dark:bg-zinc-500'
              }`}
            />
            <span className="text-zinc-500 dark:text-zinc-400">
              Go Core WS:{' '}
              <strong
                className={
                  socketStatus === 'connected'
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-zinc-500 dark:text-zinc-400'
                }
              >
                {socketStatus.toUpperCase()}
              </strong>
            </span>
          </div>

          {/* PGlite Badge */}
          <div className="flex items-center gap-1.5 bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800/80 px-3 py-1.5 rounded-lg text-xs font-mono text-blue-700 dark:text-blue-300">
            <Database className="w-3.5 h-3.5 text-blue-500" />
            <span>PGlite WASM Active</span>
          </div>

          {/* SQL Console Button */}
          <button
            onClick={() => setIsSqlConsoleOpen(true)}
            className="flex items-center gap-1.5 bg-white hover:bg-zinc-100 text-zinc-700 border-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 dark:text-white dark:border-zinc-700 border px-3 py-1.5 rounded-lg text-xs font-medium transition shadow-sm"
          >
            <Database className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400" />
            SQL Console
          </button>

          {/* Simulation Trigger Button */}
          <button
            onClick={() => setIsSimModalOpen(true)}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white transition shadow shadow-blue-500/20 dark:shadow-blue-900/40"
          >
            <Zap className="w-3.5 h-3.5 text-amber-300 fill-current" />
            Simulate Attack
          </button>

          {/* Refresh */}
          <button
            onClick={loadData}
            disabled={isRefreshing}
            className="p-1.5 bg-white hover:bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-900 dark:hover:bg-zinc-800 dark:border-zinc-800 dark:text-zinc-400 dark:hover:text-white border rounded-lg transition shadow-sm"
            title="Refresh local PGlite data"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </header>

      {/* Initialization Notice (If any error occurred) */}
      {initError && (
        <div className="mt-4 p-3 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/80 rounded-xl flex items-center justify-between text-xs text-amber-800 dark:text-amber-200">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-amber-500 shrink-0" />
            <span>Database warning: {initError}. Retrying in-memory mode.</span>
          </div>
          <button
            onClick={loadData}
            className="px-2.5 py-1 bg-amber-200 dark:bg-amber-800/60 rounded text-amber-900 dark:text-amber-100 font-medium hover:bg-amber-300 dark:hover:bg-amber-800 transition"
          >
            Retry Sync
          </button>
        </div>
      )}

      {/* Metric Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 sm:gap-4 my-6">
        <div className="bg-white dark:bg-zinc-900/80 border border-zinc-200 dark:border-zinc-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-zinc-500 dark:text-zinc-400 text-xs mb-1">
            <span>Correlated Incidents</span>
            <Flame className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-black text-zinc-900 dark:text-white font-mono">
            {incidents.length}
          </div>
          <div className="text-[10px] text-zinc-400 dark:text-zinc-500 mt-1">Multi-Stage Campaigns</div>
        </div>

        <div className="bg-white dark:bg-zinc-900/80 border border-red-200 dark:border-red-900/40 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-red-600 dark:text-red-400 text-xs mb-1">
            <span>Critical Threats</span>
            <ShieldAlert className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-2xl font-black text-red-600 dark:text-red-400 font-mono">
            {metrics.criticalCount}
          </div>
          <div className="text-[10px] text-red-500/80 dark:text-red-500/70 mt-1">Score ≥ 80 (Auto-blocked)</div>
        </div>

        <div className="bg-white dark:bg-zinc-900/80 border border-orange-200 dark:border-orange-900/40 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-orange-600 dark:text-orange-400 text-xs mb-1">
            <span>High Severity</span>
            <AlertTriangle className="w-4 h-4 text-orange-500" />
          </div>
          <div className="text-2xl font-black text-orange-600 dark:text-orange-400 font-mono">
            {metrics.highCount}
          </div>
          <div className="text-[10px] text-orange-500/80 dark:text-orange-500/70 mt-1">Score 60 – 79</div>
        </div>

        <div className="bg-white dark:bg-zinc-900/80 border border-purple-200 dark:border-purple-900/40 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-purple-600 dark:text-purple-400 text-xs mb-1">
            <span>Contained / Triaged</span>
            <CheckCircle className="w-4 h-4 text-purple-500 dark:text-purple-400" />
          </div>
          <div className="text-2xl font-black text-purple-700 dark:text-purple-300 font-mono">
            {metrics.containedCount}
          </div>
          <div className="text-[10px] text-purple-600/80 dark:text-purple-400/70 mt-1">Mitigated by SOC</div>
        </div>

        <div className="bg-white dark:bg-zinc-900/80 border border-zinc-200 dark:border-zinc-800 rounded-xl p-4 col-span-2 sm:col-span-1 shadow-sm">
          <div className="flex items-center justify-between text-zinc-500 dark:text-zinc-400 text-xs mb-1">
            <span>Avg Risk Score</span>
            <Server className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-cyan-700 dark:text-cyan-300 font-mono">
            {metrics.avgScore}
            <span className="text-xs text-zinc-400 dark:text-zinc-500 font-normal"> / 100</span>
          </div>
          <div className="text-[10px] text-zinc-400 dark:text-zinc-500 mt-1">Total Raw: {metrics.totalAlerts}</div>
        </div>
      </div>

      {/* Analytics Charts */}
      <ThreatChart alerts={alerts} />

      {/* MITRE ATT&CK Enterprise Kill-Chain Heatmap */}
      <MitreHeatmap alerts={alerts} />

      {/* Navigation View Mode Tabs (Attack Storylines vs Raw Stream) */}
      <div className="flex items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-1.5 p-1 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl shadow-xs">
          <button
            onClick={() => setActiveTab('INCIDENTS')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
              activeTab === 'INCIDENTS'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
            }`}
          >
            <Flame className="w-3.5 h-3.5" />
            Attack Storylines &amp; Incidents ({incidents.length})
          </button>

          <button
            onClick={() => setActiveTab('ALERTS')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
              activeTab === 'ALERTS'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
            }`}
          >
            <LayoutGrid className="w-3.5 h-3.5" />
            Raw Alert Feed ({alerts.length})
          </button>
        </div>

        <span className="text-xs text-zinc-400 dark:text-zinc-500 font-mono hidden sm:inline">
          Correlated by IP &bull; Asset &bull; MITRE ATT&amp;CK TTPs
        </span>
      </div>

      {/* Search & Filter Controls */}
      <div className="bg-white dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-xl p-3 mb-6 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 shadow-sm">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-zinc-400 dark:text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by IP, hash, MITRE tactic, event description, or UUID..."
            className="w-full bg-slate-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:border-blue-500 transition"
          />
        </div>

        {/* Status Filter Tabs */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1 sm:pb-0">
          <Filter className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 ml-1 mr-1 shrink-0" />
          {['ALL', 'NEW', 'ENRICHED', 'CONTAINED', 'TRIAGED', 'DISMISSED'].map(
            (status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-2.5 py-1 rounded-md text-xs font-semibold uppercase tracking-wider transition shrink-0 ${
                  statusFilter === status
                    ? 'bg-blue-600 text-white shadow'
                    : 'bg-zinc-100 hover:bg-zinc-200 text-zinc-600 hover:text-zinc-900 dark:bg-zinc-800/80 dark:hover:bg-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200'
                }`}
              >
                {status}
              </button>
            )
          )}
        </div>
      </div>

      {/* Main Content: Attack Storylines OR Raw Alert Feed */}
      {activeTab === 'INCIDENTS' ? (
        <div>
          <div className="flex items-center justify-between mb-3 px-1">
            <h2 className="text-sm uppercase font-bold tracking-wider text-zinc-700 dark:text-zinc-400 flex items-center gap-2">
              <Flame className="w-4 h-4 text-amber-500" />
              Correlated Multi-Stage Incidents ({filteredIncidents.length})
            </h2>
            <span className="text-xs text-zinc-400 dark:text-zinc-500 font-mono">
              Grouped by Attacker Infrastructure &bull; MITRE Kill-Chain
            </span>
          </div>

          {filteredIncidents.length === 0 ? (
            <div className="border border-zinc-200 dark:border-zinc-800 rounded-xl p-12 text-center bg-white dark:bg-zinc-900/30 shadow-sm">
              <ShieldAlert className="w-10 h-10 text-zinc-300 dark:text-zinc-600 mx-auto mb-3" />
              <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">
                No incidents match current filter
              </h3>
              <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
                Trigger an attack simulation above or reset your search query.
              </p>
            </div>
          ) : (
            <IncidentStoryline
              incidents={filteredIncidents}
              onActionComplete={loadData}
            />
          )}
        </div>
      ) : (
        /* Raw Alert Feed List */
        <div>
          <div className="flex items-center justify-between mb-3 px-1">
            <h2 className="text-sm uppercase font-bold tracking-wider text-zinc-700 dark:text-zinc-400 flex items-center gap-2">
              <Radio className="w-4 h-4 text-blue-500 dark:text-blue-400" />
              Live Enriched Security Alert Stream ({filteredAlerts.length})
            </h2>
            <span className="text-xs text-zinc-400 dark:text-zinc-500 font-mono">
              Client-Side PostgreSQL WASM Engine
            </span>
          </div>

          {filteredAlerts.length === 0 ? (
            <div className="border border-zinc-200 dark:border-zinc-800 rounded-xl p-12 text-center bg-white dark:bg-zinc-900/30 shadow-sm">
              <ShieldAlert className="w-10 h-10 text-zinc-300 dark:text-zinc-600 mx-auto mb-3" />
              <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">
                No matching alerts found
              </h3>
              <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
                Send an alert via HTTP webhook to <code>/api/v1/alerts/ingest</code> or click the &quot;Simulate Attack&quot; button above.
              </p>
            </div>
          ) : (
            filteredAlerts.map((alert) => (
              <AlertCard
                key={alert.alert_uuid}
                alert={alert}
                onActionComplete={loadData}
              />
            ))
          )}
        </div>
      )}

      {/* Modals */}
      <SqlConsole
        isOpen={isSqlConsoleOpen}
        onClose={() => setIsSqlConsoleOpen(false)}
      />
      <SimulationModal
        isOpen={isSimModalOpen}
        onClose={() => setIsSimModalOpen(false)}
        onAlertGenerated={loadData}
      />
    </main>
  );
}
