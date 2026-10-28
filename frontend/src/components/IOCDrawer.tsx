'use client';

import React, { useState } from 'react';
import { IOCItem, AlertRecord } from '@/types/alert';
import {
  Globe,
  Hash,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Server,
  Layers,
  Terminal,
  X,
  Compass,
  Cpu,
  Lock,
} from 'lucide-react';

interface IOCDrawerProps {
  ioc: IOCItem | null;
  onClose: () => void;
  allAlerts: AlertRecord[];
}

export const IOCDrawer: React.FC<IOCDrawerProps> = ({ ioc, onClose, allAlerts }) => {
  const [copiedType, setCopiedType] = useState<string | null>(null);

  if (!ioc) return null;

  const isIP = ioc.ioc_type === 'IP';
  const isHash = ioc.ioc_type === 'HASH';
  const isDomain = ioc.ioc_type === 'DOMAIN';

  // Find all alerts in PGlite WASM matching this IOC
  const relatedAlerts = allAlerts.filter((a) =>
    a.iocs?.some((i) => i.ioc_value.toLowerCase() === ioc.ioc_value.toLowerCase())
  );

  // Derive mock/computed threat intelligence metadata
  const geoInfo = isIP
    ? {
        country: ioc.ioc_value.startsWith('10.') || ioc.ioc_value.startsWith('192.168.') ? 'Internal RFC1918' : 'China (CN)',
        asn: ioc.ioc_value.startsWith('118.25') ? 'AS4134 Chinanet' : 'AS16509 Amazon.com',
        city: ioc.ioc_value.startsWith('118.25') ? 'Beijing' : 'Ashburn, VA',
        coordinates: '39.9042° N, 116.4074° E',
      }
    : null;

  // External intelligence links
  const vtUrl = isHash
    ? `https://www.virustotal.com/gui/file/${ioc.ioc_value}`
    : isIP
    ? `https://www.virustotal.com/gui/ip-address/${ioc.ioc_value}`
    : `https://www.virustotal.com/gui/domain/${ioc.ioc_value}`;

  const abuseUrl = isIP ? `https://www.abuseipdb.com/check/${ioc.ioc_value}` : null;
  const shodanUrl = isIP ? `https://www.shodan.io/host/${ioc.ioc_value}` : null;

  // Generated CLI Firewall Block Rules
  const firewallRules = {
    iptables: `iptables -A INPUT -s ${ioc.ioc_value} -j DROP`,
    ciscoASA: `access-list OUTSIDE_BLOCK extended deny ip host ${ioc.ioc_value} any`,
    paloAlto: `set address block_${ioc.ioc_value.replace(/[^a-zA-Z0-9]/g, '_')} ip-netmask ${ioc.ioc_value}/32`,
    powershell: isIP
      ? `New-NetFirewallRule -DisplayName "SOC_Block_${ioc.ioc_value}" -Direction Inbound -Action Block -RemoteAddress ${ioc.ioc_value}`
      : `# Hash containment rule\nBlock-FileHash -Algorithm SHA256 -Hash "${ioc.ioc_value}"`,
  };

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50 dark:bg-black/70 backdrop-blur-xs animate-in fade-in">
      <div className="bg-white dark:bg-zinc-950 border-l border-zinc-200 dark:border-zinc-800 w-full max-w-xl h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200 overflow-hidden">
        {/* Drawer Header */}
        <div className="px-6 py-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between bg-zinc-50 dark:bg-zinc-900/60 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 text-blue-600 dark:bg-blue-950/80 dark:text-blue-400 rounded-xl">
              {isIP ? <Globe className="w-5 h-5" /> : isHash ? <Hash className="w-5 h-5" /> : <Compass className="w-5 h-5" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 border border-blue-200 dark:border-blue-800">
                  {ioc.ioc_type} IOC Investigation
                </span>
                <span className="text-xs text-zinc-400 font-mono">
                  {relatedAlerts.length} Cross-Correlated Alert{relatedAlerts.length > 1 ? 's' : ''}
                </span>
              </div>
              <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white font-mono mt-0.5 truncate max-w-sm">
                {ioc.ioc_value}
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Drawer Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5 text-xs">
          {/* Quick Copy Value */}
          <div className="p-3 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-xl flex items-center justify-between">
            <div className="font-mono text-zinc-800 dark:text-zinc-200 truncate mr-2 select-all">
              {ioc.ioc_value}
            </div>
            <button
              onClick={() => copyToClipboard(ioc.ioc_value, 'val')}
              className="flex items-center gap-1 px-2.5 py-1 bg-white dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 rounded text-[11px] font-semibold text-zinc-700 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-700 transition shrink-0"
            >
              {copiedType === 'val' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedType === 'val' ? 'Copied' : 'Copy'}
            </button>
          </div>

          {/* External CTI Deep-Links */}
          <div>
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 mb-2">
              External Threat Intelligence Deep Links
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <a
                href={vtUrl}
                target="_blank"
                rel="noreferrer"
                className="p-2.5 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg hover:border-blue-500 transition flex items-center justify-between group shadow-2xs"
              >
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                  <span className="font-semibold text-zinc-800 dark:text-zinc-200">VirusTotal</span>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-zinc-400 group-hover:text-blue-500" />
              </a>

              {abuseUrl && (
                <a
                  href={abuseUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="p-2.5 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg hover:border-blue-500 transition flex items-center justify-between group shadow-2xs"
                >
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-orange-500" />
                    <span className="font-semibold text-zinc-800 dark:text-zinc-200">AbuseIPDB</span>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-zinc-400 group-hover:text-blue-500" />
                </a>
              )}

              {shodanUrl && (
                <a
                  href={shodanUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="p-2.5 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg hover:border-blue-500 transition flex items-center justify-between group shadow-2xs"
                >
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-red-500" />
                    <span className="font-semibold text-zinc-800 dark:text-zinc-200">Shodan</span>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-zinc-400 group-hover:text-blue-500" />
                </a>
              )}
            </div>
          </div>

          {/* Geolocation & Network Telemetry */}
          {geoInfo && (
            <div>
              <h4 className="text-[11px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 mb-2">
                Network &amp; Geolocation Attributes
              </h4>
              <div className="grid grid-cols-2 gap-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg p-3 text-xs">
                <div>
                  <span className="text-zinc-400 text-[10px]">Country Origin:</span>
                  <div className="font-semibold text-zinc-800 dark:text-zinc-200">{geoInfo.country}</div>
                </div>
                <div>
                  <span className="text-zinc-400 text-[10px]">Autonomous System (ASN):</span>
                  <div className="font-semibold text-zinc-800 dark:text-zinc-200">{geoInfo.asn}</div>
                </div>
                <div>
                  <span className="text-zinc-400 text-[10px]">Location:</span>
                  <div className="font-semibold text-zinc-800 dark:text-zinc-200">{geoInfo.city}</div>
                </div>
                <div>
                  <span className="text-zinc-400 text-[10px]">Coordinates:</span>
                  <div className="font-semibold text-zinc-800 dark:text-zinc-200 font-mono">{geoInfo.coordinates}</div>
                </div>
              </div>
            </div>
          )}

          {/* Instant Firewall Block Rule Generator */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-[11px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-red-500" />
                One-Click Firewall Rule Generator
              </h4>
              <span className="text-[10px] text-zinc-400">Copy syntax directly into perimeter equipment</span>
            </div>

            <div className="space-y-2">
              {Object.entries(firewallRules).map(([platform, ruleText]) => (
                <div
                  key={platform}
                  className="bg-zinc-900 border border-zinc-800 rounded-lg p-2.5 font-mono text-[11px] flex items-center justify-between gap-2 shadow-inner"
                >
                  <div className="text-emerald-400 truncate select-all">{ruleText}</div>
                  <button
                    onClick={() => copyToClipboard(ruleText, platform)}
                    className="shrink-0 px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] flex items-center gap-1 transition"
                  >
                    {copiedType === platform ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copiedType === platform ? 'Copied' : platform}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Historical Alerts in PGlite WASM */}
          <div>
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 mb-2 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-blue-500" />
              Correlated Alerts in Local PGlite DB ({relatedAlerts.length})
            </h4>

            {relatedAlerts.length === 0 ? (
              <div className="p-4 border border-zinc-200 dark:border-zinc-800 rounded-lg text-center text-zinc-400">
                No other matching alerts recorded for this indicator.
              </div>
            ) : (
              <div className="space-y-2">
                {relatedAlerts.map((a) => (
                  <div
                    key={a.alert_uuid}
                    className="p-2.5 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg flex items-center justify-between gap-2 shadow-2xs"
                  >
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono font-bold text-blue-600 dark:text-blue-400">
                          {a.alert_uuid}
                        </span>
                        <span className="font-semibold text-zinc-800 dark:text-zinc-200 truncate max-w-[200px]">
                          {a.event_type}
                        </span>
                      </div>
                      <div className="text-[10px] text-zinc-400 mt-0.5">
                        Source: {a.source} &bull; Time: {new Date(a.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-zinc-200 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200">
                        {a.calculated_score.toFixed(0)}/100
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
