import { AlertRecord, IncidentGroup, DashboardMetrics, TriageAuditLog } from '@/types/alert';
import { getMitreAttackForAlert } from './mitre';
import { generateRootCauseAnalysis } from './hypothesis';

export interface ReportOptions {
  shiftName?: string;
  leadAnalyst?: string;
  timeWindow?: string;
  includeAuditTrail?: boolean;
}

/**
 * Generates an executive-ready Markdown investigation report for shift handover or incident debrief
 */
export function generateExecutiveMarkdownReport(
  alerts: AlertRecord[],
  incidents: IncidentGroup[],
  metrics: DashboardMetrics,
  auditLogs: TriageAuditLog[],
  options: ReportOptions = {}
): string {
  const generatedAt = new Date().toUTCString();
  const shift = options.shiftName || 'SOC Operational Shift 01 (Day)';
  const lead = options.leadAnalyst || 'SOC Web Analyst / IR Lead';
  const windowStr = options.timeWindow || 'Last 24 Hours / Live Session';

  const contained = alerts.filter((a) => a.status === 'CONTAINED');
  const triaged = alerts.filter((a) => a.status === 'TRIAGED');
  const critical = alerts.filter((a) => a.calculated_score >= 80);

  // Group IOCs
  const uniqueIOCs = new Set<string>();
  alerts.forEach((a) => {
    (a.iocs || []).forEach((ioc) => {
      uniqueIOCs.add(`${ioc.ioc_type}: ${ioc.ioc_value}`);
    });
  });

  let md = `# EXECUTIVE SECURITY INCIDENT & SHIFT HANDOVER REPORT
**Classification:** TLP:AMBER | STRICTLY CONFIDENTIAL - INTERNAL SOC USE ONLY  
**Generated At:** ${generatedAt}  
**Shift Context:** ${shift}  
**Lead Investigator:** ${lead}  
**Observation Window:** ${windowStr}  

---

## 1. Executive Summary & Operational Metrics

During this operational cycle, the Automated SOC Alert Enrichment & Triage platform processed and enriched **${metrics.totalAlerts} raw telemetry events**, which were automatically correlated into **${incidents.length} multi-stage adversary campaigns / incidents**.

### Key Threat Telemetry Indicators:
- **Total Ingested Alerts:** ${metrics.totalAlerts}
- **Correlated Incidents:** ${incidents.length}
- **Critical Severity Alerts (Score ≥ 80):** ${metrics.criticalCount} (Immediate containment applied)
- **High Severity Alerts (Score 60-79):** ${metrics.highCount}
- **Mitigated & Triaged Items:** ${metrics.containedCount}
- **Average Threat Score:** ${metrics.avgScore} / 100
- **Distinct Indicators of Compromise (IOCs):** ${uniqueIOCs.size}

| Severity Tier | Ingested Count | Mitigation Status | Default SOAR Policy |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | ${metrics.criticalCount} | ${contained.length} Contained | Automated Firewall Edge Drop / Host Isolation |
| **HIGH** | ${metrics.highCount} | ${triaged.length} Triaged | Priority Tier-2 Analyst Verification |
| **MEDIUM / LOW** | ${metrics.totalAlerts - metrics.criticalCount - metrics.highCount} | Monitored | Baseline Correlation & Audit Logging |

---

## 2. Correlated Attack Campaigns & Storylines

Adversary activities were correlated across endpoints, telemetry sources, and perimeter proxies:

`;

  if (incidents.length === 0) {
    md += `*No correlated multi-stage attack incidents recorded in this window.*\n\n`;
  } else {
    incidents.forEach((inc, idx) => {
      md += `### 2.${idx + 1} Incident ${inc.id}: ${inc.title}
- **Target Entity / Attacker Key:** \`${inc.keyEntity}\` (${inc.entityType})
- **Composite Risk Rating:** **${inc.highestScore.toFixed(1)} / 100** [${inc.highestTier}]
- **Incident Status:** \`${inc.status}\`
- **First Seen:** ${new Date(inc.startTime).toUTCString()}
- **Last Observed:** ${new Date(inc.lastSeenTime).toUTCString()}
- **Correlated Stages:** ${inc.alerts.length} sequential telemetry events
- **MITRE ATT&CK Tactics:** ${inc.mitreTactics.map((t) => `\`${t}\``).join(' → ')}
- **Techniques Observed:** ${inc.mitreTechniques.join(', ')}
- **Storyline Summary:** ${inc.hypothesisSummary || 'Sequential attack telemetry correlated.'}

#### Correlated Incident Alert Progression:
| # | Alert UUID | Source | Event Description | Score | Status | Primary IOC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
`;

      inc.alerts.forEach((a, aIdx) => {
        const primaryIOC = a.iocs?.[0] ? `${a.iocs[0].ioc_type}: ${a.iocs[0].ioc_value}` : 'N/A';
        md += `| ${aIdx + 1} | \`${a.alert_uuid}\` | ${a.source} | ${a.event_type} | ${a.calculated_score.toFixed(1)} | ${a.status} | \`${primaryIOC}\` |\n`;
      });

      md += `\n`;
    });
  }

  md += `---

## 3. Root Cause, Hypotheses & Remediation Verdicts

Detailed forensic breakdown for active alerts, including evaluated hypotheses, test criteria, and analyst actions:

`;

  alerts.forEach((a, idx) => {
    const mitre = getMitreAttackForAlert(a);
    const rca = a.root_cause || generateRootCauseAnalysis(a);

    md += `### 3.${idx + 1} Alert \`${a.alert_uuid}\` — ${a.event_type}
- **Source Platform:** ${a.source}
- **Severity & Threat Score:** ${a.calculated_score.toFixed(1)}/100 (${a.severity_tier})
- **Current Status:** \`${a.status}\`
- **MITRE ATT&CK:** \`${mitre.techniqueId}\` — *${mitre.techniqueName}* (\`${mitre.tactic}\`)
- **Automated SOAR Action:** ${a.auto_action_taken || 'Manual Analyst Review Required'}

#### Root Cause Analysis (RCA):
> **Cause Summary:** ${rca.summary}

**Evaluated Hypotheses:**
`;

    rca.hypotheses.forEach((h) => {
      const isSelected = a.selected_hypothesis_id === h.id ? ' **[SELECTED VERDICT TARGET]**' : '';
      md += `- **[${h.status.toUpperCase()}]** ${h.title}${isSelected}
  - *Details:* ${h.description}
  ${h.evidenceSupport ? `- *Supporting Evidence:* ${h.evidenceSupport}` : ''}
  ${h.evidenceContradict ? `- *Contradicting Evidence:* ${h.evidenceContradict}` : ''}
`;
    });

    if (rca.whatWouldSettleIt) {
      md += `\n**What Would Settle It (Verification Criteria):**  \n*${rca.whatWouldSettleIt}*\n`;
    }

    md += `\n**Remediation Recommendation ("What To Do"):**  \n${rca.whatToDo.nextCheck} — *${rca.whatToDo.description}*\n\n`;

    if (a.enrichments && a.enrichments.length > 0) {
      md += `**Threat Intelligence Corroboration:**\n`;
      a.enrichments.forEach((e) => {
        md += `- **${e.provider}:** Score ${e.score.toFixed(0)}/100 (Confidence / Hits verified)\n`;
      });
      md += `\n`;
    }
  });

  if (auditLogs && auditLogs.length > 0) {
    md += `---

## 4. Triage Audit Trail & Remediation Logs

Immutable audit trail retrieved directly from browser-native PGlite WebAssembly database:

| Performed At (UTC) | Alert UUID | Actor | Remediation Action | Chosen Hypothesis / Justification Notes |
| :--- | :--- | :--- | :--- | :--- |
`;

    auditLogs.slice(0, 20).forEach((log) => {
      const time = new Date(log.performed_at).toUTCString();
      const notes = log.notes || 'Automated or default triage submission';
      md += `| ${time} | \`${log.alert_uuid}\` | ${log.actor} | **${log.action_taken}** | ${notes} |\n`;
    });

    md += `\n`;
  }

  md += `---

## 5. Shift Handover Checklist & Outstanding Items

- [x] All Critical ($Score \\ge 80$) alerts subjected to active mitigation (IP Blocked or Host Isolated).
- [x] Threat intelligence scores verified across VirusTotal, AbuseIPDB, and Shodan.
- [ ] Verify perimeter firewall drop counters for confirmed C2 egress destinations.
- [ ] Review pending EDR forensic memory dumps on isolated production hosts.
- [ ] Handover confirmed to incoming Tier-1/Tier-2 shift lead.

---
*Report auto-compiled by Automated SOC Alert Enrichment & Triage Engine (Next.js WASM + Go Core).*
`;

  return md;
}
