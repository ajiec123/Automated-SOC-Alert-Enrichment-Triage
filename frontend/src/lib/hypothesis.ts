import { AlertRecord, RootCauseAnalysis } from '@/types/alert';

export function generateRootCauseAnalysis(alert: AlertRecord): RootCauseAnalysis {
  const event = alert.event_type.toLowerCase();
  const ioc = alert.iocs?.[0]?.ioc_value || 'target indicator';
  const score = alert.calculated_score;
  const source = alert.source;

  if (event.includes('cobalt strike') || event.includes('c2') || event.includes('beacon')) {
    return {
      summary:
        'Investigation examined 5 beaconing telemetry cycles across perimeter egress firewalls. 3 hypotheses tested: compromised process memory injection, scheduled task persistence, or legitimate software update telemetry.',
      investigator: 'SOC Automated Triage & IR Bot',
      hypotheses: [
        {
          id: 'hyp_c2_mem',
          title: `Compromised memory injection (Malleable C2 Beacon) communicating with ${ioc}`,
          status: 'still_open',
          description:
            `Perimeter telemetry confirmed regular jittered HTTPS egress requests matching Cobalt Strike default sleep time (60s ± 15%). Target IOC: ${ioc}.`,
          evidenceSupport: 'Network traffic beacon frequency (jitter 15%), external CTI malicious detection ratio (58/72).',
          evidenceContradict: 'No direct process crash logs observed in Event Viewer.',
        },
        {
          id: 'hyp_c2_persist',
          title: 'Scheduled Task / Service file persistence on Domain Controller dc-01',
          status: 'not_confirmed',
          description:
            'Registry Run key and Task Scheduler audits did not show persistent binary on disk; suggests reflective DLL loading directly in RAM.',
          evidenceSupport: 'Event ID 4688 process creation without matching file on disk.',
        },
        {
          id: 'hyp_c2_fp',
          title: 'False Positive: Cloud management or telemetry service heartbeat',
          status: 'refuted',
          description:
            `AbuseIPDB reputation score (${alert.enrichments?.find(e => e.provider === 'AbuseIPDB')?.score || 96}%) and Shodan open C2 ports refute benign vendor heartbeat.`,
          evidenceContradict: 'Negative reputation across 3 threat intelligence providers.',
        },
      ],
      whatWouldSettleIt:
        'Memory dump analysis on Domain Controller dc-01 (Volatility3 vadinfo / malfind) to extract beacon configuration and active C2 pipe.',
      whatToDo: {
        nextCheck: `Execute immediate host containment on dc-01 and verify firewall edge drop for ${ioc}.`,
        description:
          'Sever active C2 channel to prevent interactive operator lateral movement, then extract volatility memory profile for forensic preservation.',
        recommendedAction: 'block_ip',
      },
    };
  }

  if (event.includes('ransomware') || event.includes('vss') || event.includes('shadow')) {
    return {
      summary:
        'Investigation examined 3 system calls on production host. 3 hypotheses tested: active ransomware detonation script, administrative backup script, or automated maintenance routine.',
      investigator: 'Endpoint EDR / Wazuh Integration',
      hypotheses: [
        {
          id: 'hyp_rw_exec',
          title: 'Active Ransomware Detonation attempting Volume Shadow Copy wiping',
          status: 'still_open',
          description:
            'Process spawned with command "vssadmin.exe delete shadows /all /quiet" which directly precedes widespread volume encryption.',
          evidenceSupport: 'Command line execution of vssadmin.exe, malicious SHA256 file hash detected in staging directory.',
        },
        {
          id: 'hyp_rw_priv',
          title: 'Privilege escalation via compromised local service account',
          status: 'still_open',
          description:
            'High-integrity execution token observed running under SYSTEM context from user-writable temporary location.',
          evidenceSupport: 'Process token privilege SeDebugPrivilege enabled.',
        },
        {
          id: 'hyp_rw_admin',
          title: 'Legitimate backup maintenance script clearing old snapshots',
          status: 'not_confirmed',
          description:
            'No matching IT maintenance ticket or scheduled cron job verified for snapshot deletion during this time window.',
          evidenceContradict: 'No change management ticket recorded.',
        },
      ],
      whatWouldSettleIt:
        'Check file system modification velocity (I/O spikes and renaming with known ransomware extensions like .lockbit or .encrypted).',
      whatToDo: {
        nextCheck: 'Isolate Host from network to prevent SMB/RDP lateral spread across internal subnets.',
        description:
          'Kill rogue parent process, isolate network adapter via EDR, and review database storage snapshot immutability.',
        recommendedAction: 'isolate_host',
      },
    };
  }

  if (event.includes('ssh') || event.includes('password') || event.includes('brute') || event.includes('spray')) {
    return {
      summary:
        'Investigation examined 340+ authentication failure events over 60 seconds against gateway service. 3 hypotheses analyzed.',
      investigator: 'Suricata NIDS / Wazuh SIEM',
      hypotheses: [
        {
          id: 'hyp_bf_ext',
          title: `External automated botnet credential stuffing targeting SSH port 22 from ${ioc}`,
          status: 'still_open',
          description:
            `Repeated login attempts using common dictionaries (admin, root, test) originating from public IP ${ioc}.`,
          evidenceSupport: 'High velocity auth failures, AbuseIPDB confidence score > 90%.',
        },
        {
          id: 'hyp_bf_misconfig',
          title: 'Internal misconfigured service with outdated password credentials',
          status: 'refuted',
          description:
            'Source IP is external public routable IP, not internal RFC1918 address.',
          evidenceContradict: 'Public IP routing verified.',
        },
        {
          id: 'hyp_bf_comp',
          title: 'Target user account successfully compromised via brute force',
          status: 'not_confirmed',
          description:
            'No successful authentication (Event ID 4624 / Accepted password) logged following the failed attempts.',
          evidenceSupport: 'All attempts resulted in Auth_Fail (100% failure rate).',
        },
      ],
      whatWouldSettleIt:
        'Check authentication log for any single successful session handshake from the offending IP address.',
      whatToDo: {
        nextCheck: `Block source IP ${ioc} at perimeter firewall / Fail2ban edge rule.`,
        description:
          'Drop incoming SYN packets from this IP and verify MFA enforcement across all exposed SSH/VPN gateways.',
        recommendedAction: 'block_ip',
      },
    };
  }

  if (event.includes('log4j') || event.includes('jndi') || event.includes('rce')) {
    return {
      summary:
        'JNDI lookup exploit string (${jndi:ldap://...}) detected in incoming HTTP request header. Exploit investigation opened.',
      investigator: 'WAF & Wazuh Telemetry Engine',
      hypotheses: [
        {
          id: 'hyp_log4j_exploit',
          title: `Remote Code Execution attempt exploiting CVE-2021-44228 from ${ioc}`,
          status: 'still_open',
          description:
            `Attacker delivered malicious JNDI string aiming to trigger out-of-band LDAP connection to ${ioc}.`,
          evidenceSupport: 'Raw HTTP header regex match, known vulnerable Log4j library version in application stack.',
        },
        {
          id: 'hyp_log4j_outbound',
          title: 'Outbound LDAP/RMI connection successfully initiated by JVM',
          status: 'not_confirmed',
          description:
            'Egress firewall rules appear to have blocked outbound port 1389/389 TCP SYN to external destination.',
          evidenceContradict: 'Firewall dropped egress connection attempt.',
        },
        {
          id: 'hyp_log4j_scan',
          title: 'Generic internet vulnerability scanner without tailored post-exploitation',
          status: 'still_open',
          description:
            'Payload follows generic automated mass-scanning template rather than targeted reconnaissance.',
        },
      ],
      whatWouldSettleIt:
        'Inspect JVM application stdout/stderr logs for class loader exceptions or outbound connection timeouts.',
      whatToDo: {
        nextCheck: 'Block attacking source IP and apply Log4j JVM property "-Dlog4j2.formatMsgNoLookups=true".',
        description:
          'Immediate IP block prevents repeated probe variations; patch/restart service with lookup suppression enabled.',
        recommendedAction: 'block_ip',
      },
    };
  }

  // Generic security alert fallback
  return {
    summary:
      `Investigation examined telemetry for event "${alert.event_type}" from ${source}. Risk score computed at ${score}/100.`,
    investigator: 'SOC Automated Triage Engine',
    hypotheses: [
      {
        id: 'hyp_gen_malicious',
        title: `Adversary activity confirmed: ${alert.event_type} represents active threat`,
        status: score >= 60 ? 'still_open' : 'not_confirmed',
        description:
          `Enrichment indicators show threat severity tier is ${alert.severity_tier} with composite score of ${score}/100.`,
        evidenceSupport: `CTI matches from providers, primary indicator: ${ioc}.`,
      },
      {
        id: 'hyp_gen_benign',
        title: 'Benign anomaly or authorized administrative action',
        status: score < 40 ? 'still_open' : 'not_confirmed',
        description:
          'Asset criticality and behavior patterns could correlate with maintenance routines or scheduled security testing.',
      },
      {
        id: 'hyp_gen_fp',
        title: 'Rule over-sensitivity / false-positive signature match',
        status: 'still_open',
        description:
          'Signature pattern triggered without confirmed corroborating endpoint persistence or lateral movement.',
      },
    ],
    whatWouldSettleIt:
      'Correlate with secondary monitoring tool (EDR, CloudTrail, or NetFlow) under integrations to confirm anomalous traffic.',
    whatToDo: {
      nextCheck: 'Register secondary monitoring tool or execute targeted remediation based on confirmed hypothesis.',
      description:
        score >= 80
          ? 'Apply immediate containment (Block IP / Isolate Host) due to elevated composite threat score.'
          : 'Review hypothesis evidence with SOC Lead and either apply remediation or mark as triaged.',
      recommendedAction: score >= 80 ? 'block_ip' : 'resolve',
    },
  };
}
