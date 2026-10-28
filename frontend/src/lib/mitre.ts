import { AlertRecord, MitreAttack, IncidentGroup, SeverityTier } from '@/types/alert';

/**
 * Maps security alerts to standard MITRE ATT&CK Enterprise Tactics & Techniques
 */
export function getMitreAttackForAlert(alert: AlertRecord): MitreAttack {
  if (alert.mitre) return alert.mitre;

  const event = (alert.event_type || '').toLowerCase();
  const rawMetadata = JSON.stringify(alert).toLowerCase();

  // 1. Command and Control (Cobalt Strike, Beaconing, Egress)
  if (event.includes('cobalt strike') || event.includes('c2') || event.includes('beacon') || rawMetadata.includes('beaconing')) {
    return {
      tactic: 'Command and Control',
      techniqueId: 'T1071.001',
      techniqueName: 'Application Layer Protocol: Web Protocols',
      subtechnique: 'HTTPS C2 Beaconing',
    };
  }

  // 2. Impact / Ransomware (VSS shadow deletion, file encryption)
  if (event.includes('ransomware') || event.includes('vss') || event.includes('shadow') || event.includes('encrypt')) {
    return {
      tactic: 'Impact',
      techniqueId: 'T1486',
      techniqueName: 'Data Encrypted for Impact',
      subtechnique: 'Shadow Copy Deletion (T1490)',
    };
  }

  // 3. Credential Access / Password Spray / Brute Force
  if (event.includes('password spray') || event.includes('bruteforce') || event.includes('ssh') || event.includes('failed login')) {
    return {
      tactic: 'Credential Access',
      techniqueId: 'T1110.003',
      techniqueName: 'Brute Force: Password Spraying',
      subtechnique: 'Network Protocol Auth Guessing',
    };
  }

  // 4. Initial Access / Exploit Public-Facing Application (Log4j, RCE, CVE-2021-44228)
  if (event.includes('log4j') || event.includes('jndi') || event.includes('rce') || event.includes('cve-2021-44228')) {
    return {
      tactic: 'Initial Access',
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      subtechnique: 'JNDI / Remote Code Execution',
    };
  }

  // 5. Discovery / Network Port Scan
  if (event.includes('port scan') || event.includes('reconnaissance') || event.includes('syn stealth') || event.includes('sweep')) {
    return {
      tactic: 'Reconnaissance',
      techniqueId: 'T1046',
      techniqueName: 'Network Service Discovery',
      subtechnique: 'SYN Port Sweep',
    };
  }

  // 6. Lateral Movement / Kerberoasting / Pass the Hash
  if (event.includes('kerberoast') || event.includes('lateral') || event.includes('ticket') || event.includes('smb')) {
    return {
      tactic: 'Lateral Movement',
      techniqueId: 'T1558.003',
      techniqueName: 'Steal or Forge Kerberos Tickets: Kerberoasting',
      subtechnique: 'TGS Request Exploitation',
    };
  }

  // 7. Privilege Escalation
  if (event.includes('privilege') || event.includes('uac') || event.includes('token') || event.includes('sedebugprivilege')) {
    return {
      tactic: 'Privilege Escalation',
      techniqueId: 'T1068',
      techniqueName: 'Exploitation for Privilege Escalation',
    };
  }

  // Default fallback
  return {
    tactic: 'Execution',
    techniqueId: 'T1204',
    techniqueName: 'User Execution / Suspicious Activity',
  };
}

/**
 * Standard MITRE ATT&CK Matrix Kill-Chain ordering
 */
export const MITRE_TACTIC_ORDER = [
  'Reconnaissance',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

/**
 * Correlates an array of individual AlertRecords into grouped Multi-Stage Incidents / Attack Storylines.
 * Grouping logic:
 *   1. Matches by common primary IP (IOC)
 *   2. Or matches by target asset ID (e.g. "dc-01", "payment-gw")
 */
export function correlateAlertsIntoIncidents(alerts: AlertRecord[]): IncidentGroup[] {
  if (!alerts || alerts.length === 0) return [];

  const groupMap = new Map<string, AlertRecord[]>();

  for (const alert of alerts) {
    const mitre = getMitreAttackForAlert(alert);
    const enrichedAlert: AlertRecord = { ...alert, mitre };

    // Grouping key: Primary IP IOC > Asset ID > Fallback UUID
    const primaryIP = alert.iocs?.find((i) => i.ioc_type === 'IP')?.ioc_value;
    const assetId = alert.asset_id;

    let key = '';
    if (primaryIP && primaryIP !== '127.0.0.1') {
      key = `ip:${primaryIP}`;
    } else if (assetId) {
      key = `asset:${assetId}`;
    } else {
      key = `event:${alert.event_type.split(' ')[0]}`;
    }

    if (!groupMap.has(key)) {
      groupMap.set(key, []);
    }
    groupMap.get(key)!.push(enrichedAlert);
  }

  const incidents: IncidentGroup[] = [];

  groupMap.forEach((groupAlerts, key) => {
    // Sort chronological: oldest to newest
    groupAlerts.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

    const isIP = key.startsWith('ip:');
    const entityValue = key.replace(/^(ip|asset|event):/, '');
    const highestAlert = [...groupAlerts].sort((a, b) => b.calculated_score - a.calculated_score)[0];

    const highestScore = highestAlert.calculated_score;
    let highestTier: SeverityTier = 'LOW';
    if (highestScore >= 80) highestTier = 'CRITICAL';
    else if (highestScore >= 60) highestTier = 'HIGH';
    else if (highestScore >= 30) highestTier = 'MEDIUM';

    // Unique Tactics & Techniques
    const tacticsSet = new Set<string>();
    const techniquesSet = new Set<string>();

    groupAlerts.forEach((a) => {
      if (a.mitre) {
        tacticsSet.add(a.mitre.tactic);
        techniquesSet.add(`${a.mitre.techniqueId} ${a.mitre.techniqueName}`);
      }
    });

    // Check overall status: if any alert is still NEW or ENRICHED, incident is open
    let incidentStatus = highestAlert.status;
    const hasOpenAlerts = groupAlerts.some((a) => a.status === 'NEW' || a.status === 'ENRICHED');
    if (hasOpenAlerts && incidentStatus === 'CONTAINED') {
      // Keep contained status if active remediation occurred
      incidentStatus = 'CONTAINED';
    }

    const title = isIP
      ? `Threat Campaign Originating from IP ${entityValue}`
      : `Host Intrusion Campaign against ${entityValue}`;

    incidents.push({
      id: `INC-${Math.abs(hashString(key)).toString(16).substring(0, 6).toUpperCase()}`,
      title,
      keyEntity: entityValue,
      entityType: isIP ? 'IP' : 'ASSET',
      highestScore,
      highestTier,
      status: incidentStatus,
      alerts: groupAlerts,
      mitreTactics: Array.from(tacticsSet),
      mitreTechniques: Array.from(techniquesSet),
      startTime: groupAlerts[0].created_at,
      lastSeenTime: groupAlerts[groupAlerts.length - 1].created_at,
      hypothesisSummary:
        groupAlerts.length > 1
          ? `Adversary correlated across ${groupAlerts.length} distinct alert stages spanning ${tacticsSet.size} MITRE ATT&CK tactics.`
          : `Single-stage detection tagged under tactic: ${Array.from(tacticsSet)[0] || 'Execution'}.`,
    });
  });

  // Sort incidents by highest score descending
  incidents.sort((a, b) => b.highestScore - a.highestScore);

  return incidents;
}

function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return hash;
}
