'use client';

import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  PieChart,
  Pie,
} from 'recharts';
import { AlertRecord } from '@/types/alert';

interface ThreatChartProps {
  alerts: AlertRecord[];
}

export const ThreatChart: React.FC<ThreatChartProps> = ({ alerts }) => {
  // Aggregate severity distribution
  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };

  alerts.forEach((a) => {
    if (a.calculated_score >= 80) severityCounts.CRITICAL++;
    else if (a.calculated_score >= 60) severityCounts.HIGH++;
    else if (a.calculated_score >= 30) severityCounts.MEDIUM++;
    else severityCounts.LOW++;
  });

  const barData = [
    { name: 'Critical (≥80)', count: severityCounts.CRITICAL, fill: '#EF4444' },
    { name: 'High (60-79)', count: severityCounts.HIGH, fill: '#F97316' },
    { name: 'Medium (30-59)', count: severityCounts.MEDIUM, fill: '#F59E0B' },
    { name: 'Low (0-29)', count: severityCounts.LOW, fill: '#10B981' },
  ];

  // Aggregate status distribution
  const statusCounts: Record<string, number> = {};
  alerts.forEach((a) => {
    statusCounts[a.status] = (statusCounts[a.status] || 0) + 1;
  });

  const pieData = Object.entries(statusCounts).map(([k, v]) => ({
    name: k,
    value: v,
  }));

  const pieColors = ['#A855F7', '#3B82F6', '#06B6D4', '#71717A', '#F59E0B'];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
      {/* Severity Breakdown Bar Chart */}
      <div className="bg-zinc-900/70 border border-zinc-800 rounded-xl p-4">
        <h4 className="text-xs uppercase font-bold tracking-wider text-zinc-400 mb-3">
          Threat Severity Distribution (Deterministic Risk Scores)
        </h4>
        <div className="h-44">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} margin={{ top: 5, right: 10, left: -25, bottom: 5 }}>
              <XAxis dataKey="name" stroke="#71717A" fontSize={11} tickLine={false} />
              <YAxis stroke="#71717A" fontSize={11} allowDecimals={false} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#18181B',
                  borderColor: '#27272A',
                  color: '#fff',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {barData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Triage Status Breakdown */}
      <div className="bg-zinc-900/70 border border-zinc-800 rounded-xl p-4">
        <h4 className="text-xs uppercase font-bold tracking-wider text-zinc-400 mb-3">
          Triage & Containment Status (PGlite Local WASM DB)
        </h4>
        <div className="h-44 flex items-center justify-center">
          {pieData.length === 0 ? (
            <div className="text-xs text-zinc-500">No alerts ingested yet</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={38}
                  outerRadius={65}
                  paddingAngle={4}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={false}
                  fontSize={10}
                >
                  {pieData.map((entry, index) => (
                    <Cell
                      key={`pie-${index}`}
                      fill={pieColors[index % pieColors.length]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#18181B',
                    borderColor: '#27272A',
                    color: '#fff',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
};
