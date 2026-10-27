'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { AlertRecord, AlertStatus, DashboardMetrics } from '@/types/alert';
import { fetchAlertsFromPGlite, fetchDashboardMetrics } from '@/lib/pglite';
import { useAlertWebSocket } from '@/lib/websocket';
import { AlertCard } from '@/components/AlertCard';
import { ThreatChart } from '@/components/ThreatChart';
import { SqlConsole } from '@/components/SqlConsole';
import { SimulationModal } from '@/components/SimulationModal';
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
  const [isSqlConsoleOpen, setIsSqlConsoleOpen] = useState(false);
  const [isSimModalOpen, setIsSimModalOpen] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [mounted, setMounted] = useState(false);

  // Load alerts and metrics directly from browser-native PGlite WASM
  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const data = await fetchAlertsFromPGlite(statusFilter);
      const m = await fetchDashboardMetrics();
      setAlerts(data);
      setMetrics(m);
    } catch (err) {
      console.error('Error querying PGlite database:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, [statusFilter]);

  // Connect WebSocket to Go backend - on any stream event, re-query PGlite
  const { status: socketStatus } = useAlertWebSocket(() => {
    loadData();
  });

  useEffect(() => {
    setMounted(true);
    loadData();
  }, [loadData]);

  if (!mounted) {
    return (
      <div className="flex h-screen items-center justify-center bg-zinc-950 text-zinc-400 font-mono text-sm">
        <div className="flex items-center gap-3">
          <Database className="w-5 h-5 text-blue-500 animate-spin" />
          Initializing Browser-WASM PGlite PostgreSQL Engine...
        </div>
      </div>
    );
  }

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

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto">
      {/* Top Header */}
      <header className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-zinc-800">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-blue-600/20 border border-blue-500/30 rounded-xl text-blue-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white flex items-center gap-2">
                Automated SOC Alert Triage Platform
                <span className="text-xs font-mono font-semibold bg-zinc-800 border border-zinc-700 px-2 py-0.5 rounded text-zinc-300">
                  SIEM &bull; SOAR
                </span>
              </h1>
              <p className="text-xs text-zinc-400">
                Go High-Throughput Ingestion &bull; Concurrent CTI Fan-Out &bull; Browser-Native PGlite PostgreSQL Engine
              </p>
            </div>
          </div>
        </div>

        {/* Engine Status Indicators & Action Bar */}
        <div className="flex flex-wrap items-center gap-2.5 self-stretch md:self-auto justify-end">
          {/* WebSocket Status */}
          <div className="flex items-center gap-2 bg-zinc-900 border border-zinc-800 px-3 py-1.5 rounded-lg text-xs font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                socketStatus === 'connected'
                  ? 'bg-emerald-400 animate-pulse'
                  : 'bg-zinc-500'
              }`}
            />
            <span className="text-zinc-400">
              Go Core WS:{' '}
              <strong
                className={
                  socketStatus === 'connected' ? 'text-emerald-400' : 'text-zinc-400'
                }
              >
                {socketStatus.toUpperCase()}
              </strong>
            </span>
          </div>

          {/* PGlite Badge */}
          <div className="flex items-center gap-1.5 bg-blue-950/50 border border-blue-800/80 px-3 py-1.5 rounded-lg text-xs font-mono text-blue-300">
            <Database className="w-3.5 h-3.5" />
            <span>PGlite WASM Active</span>
          </div>

          {/* SQL Console Button */}
          <button
            onClick={() => setIsSqlConsoleOpen(true)}
            className="flex items-center gap-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 px-3 py-1.5 rounded-lg text-xs font-medium text-white transition shadow"
          >
            <Database className="w-3.5 h-3.5 text-blue-400" />
            SQL Console
          </button>

          {/* Simulation Trigger Button */}
          <button
            onClick={() => setIsSimModalOpen(true)}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white transition shadow shadow-blue-900/40"
          >
            <Zap className="w-3.5 h-3.5 text-amber-300 fill-current" />
            Simulate Attack
          </button>

          {/* Refresh */}
          <button
            onClick={loadData}
            disabled={isRefreshing}
            className="p-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded-lg text-zinc-400 hover:text-white transition"
            title="Refresh local PGlite data"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </header>

      {/* Metric Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 sm:gap-4 my-6">
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-zinc-400 text-xs mb-1">
            <span>Total Ingested</span>
            <Layers className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">
            {metrics.totalAlerts}
          </div>
          <div className="text-[10px] text-zinc-500 mt-1">Stored in PGlite WASM</div>
        </div>

        <div className="bg-zinc-900/80 border border-red-900/40 rounded-xl p-4">
          <div className="flex items-center justify-between text-red-400 text-xs mb-1">
            <span>Critical Threats</span>
            <ShieldAlert className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-2xl font-black text-red-400 font-mono">
            {metrics.criticalCount}
          </div>
          <div className="text-[10px] text-red-500/70 mt-1">Score ≥ 80 (Auto-blocked)</div>
        </div>

        <div className="bg-zinc-900/80 border border-orange-900/40 rounded-xl p-4">
          <div className="flex items-center justify-between text-orange-400 text-xs mb-1">
            <span>High Severity</span>
            <AlertTriangle className="w-4 h-4 text-orange-500" />
          </div>
          <div className="text-2xl font-black text-orange-400 font-mono">
            {metrics.highCount}
          </div>
          <div className="text-[10px] text-orange-500/70 mt-1">Score 60 – 79</div>
        </div>

        <div className="bg-zinc-900/80 border border-purple-900/40 rounded-xl p-4">
          <div className="flex items-center justify-between text-purple-400 text-xs mb-1">
            <span>Contained / Triaged</span>
            <CheckCircle className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-black text-purple-300 font-mono">
            {metrics.containedCount}
          </div>
          <div className="text-[10px] text-purple-400/70 mt-1">Mitigated by SOC</div>
        </div>

        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4 col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-zinc-400 text-xs mb-1">
            <span>Avg Risk Score</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-cyan-300 font-mono">
            {metrics.avgScore}
            <span className="text-xs text-zinc-500 font-normal"> / 100</span>
          </div>
          <div className="text-[10px] text-zinc-500 mt-1">Multi-CTI Weighted</div>
        </div>
      </div>

      {/* Analytics Charts */}
      <ThreatChart alerts={alerts} />

      {/* Search & Filter Controls */}
      <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-3 mb-6 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by IP, hash, event description, source, or alert UUID..."
            className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-blue-500 transition"
          />
        </div>

        {/* Status Filter Tabs */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1 sm:pb-0">
          <Filter className="w-3.5 h-3.5 text-zinc-500 ml-1 mr-1 shrink-0" />
          {['ALL', 'NEW', 'ENRICHED', 'CONTAINED', 'TRIAGED', 'DISMISSED'].map(
            (status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-2.5 py-1 rounded-md text-xs font-semibold uppercase tracking-wider transition shrink-0 ${
                  statusFilter === status
                    ? 'bg-blue-600 text-white shadow'
                    : 'bg-zinc-800/80 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {status}
              </button>
            )
          )}
        </div>
      </div>

      {/* Alert Feed List */}
      <div>
        <div className="flex items-center justify-between mb-3 px-1">
          <h2 className="text-sm uppercase font-bold tracking-wider text-zinc-400 flex items-center gap-2">
            <Radio className="w-4 h-4 text-blue-400" />
            Live Enriched Security Alert Stream ({filteredAlerts.length})
          </h2>
          <span className="text-xs text-zinc-500 font-mono">
            Client-Side PostgreSQL WASM Engine
          </span>
        </div>

        {filteredAlerts.length === 0 ? (
          <div className="border border-zinc-800 rounded-xl p-12 text-center bg-zinc-900/30">
            <ShieldAlert className="w-10 h-10 text-zinc-600 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-zinc-300">
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
