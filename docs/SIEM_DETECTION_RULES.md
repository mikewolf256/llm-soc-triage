# SIEM Detection Rules for IDOR Monitoring

## Overview

This document provides detection rules in multiple SIEM formats for ingesting IDOR detection events from the `llm-soc-triage` middleware. These rules enable centralized monitoring, alerting, and threat hunting across security platforms.

---

## Sigma Rule (Universal SIEM Format)

Sigma rules can be converted to Splunk, Elastic, QRadar, and other SIEM query languages using `sigmac`.

```yaml
title: IDOR Enumeration Attack Detected
id: a3f8b2c1-d4e5-f6a7-b8c9-d0e1f2a3b4c5
status: production
description: Detects ownership-aware IDOR enumeration attacks from llm-soc-triage middleware
author: Agentic Security Partners LLC
date: 2026/01/27
modified: 2026/01/27
references:
    - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
    - https://attack.mitre.org/techniques/T1213/
logsource:
    product: llm-soc-triage
    service: idor_detection
    category: application
detection:
    selection:
        event_type: 'idor_detection_event'
        severity:
            - 'CRITICAL_IDOR_ATTACK'
            - 'ALERT_MEDIUM'
        distinct_resources_accessed|gte: 3
        is_sequential: true
    filter_qa:
        user_tags:
            - 'qa_automation'
            - 'pentester'
    condition: selection and not filter_qa
falsepositives:
    - QA testing accounts with appropriate tags
    - Internal penetration testing (should be tagged)
    - Legitimate customer support agents with multi-account access
level: critical
tags:
    - attack.collection
    - attack.t1213
    - attack.t1213.002
    - owasp.a01
    - idor
    - web_application
fields:
    - event_id
    - user_id
    - session_id
    - failed_resources
    - resource_owners
    - time_window_seconds
    - mitre_tactics
    - mitre_techniques
```

---

## Splunk SPL (Search Processing Language)

### Detection Search

```spl
index=security sourcetype="llm-soc-triage:idor_detection"
| search severity IN ("CRITICAL_IDOR_ATTACK", "ALERT_MEDIUM")
| search distinct_resources_accessed >= 3
| search is_sequential=true
| search NOT user_tags IN ("qa_automation", "pentester")
| eval detection_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table detection_time event_id user_id session_id severity distinct_resources_accessed failed_resources resource_owners mitre_tactics mitre_techniques
| sort -_time
```

### Correlation Search (Scheduled Alert)

```spl
index=security sourcetype="llm-soc-triage:idor_detection" severity="CRITICAL_IDOR_ATTACK"
| search NOT user_tags IN ("qa_automation", "pentester")
| eval attack_velocity=distinct_resources_accessed/time_window_seconds
| where attack_velocity > 0.05
| table _time event_id user_id session_id attack_velocity failed_resources mitre_techniques
| outputlookup idor_incidents_last_24h
| sendalert soar_webhook
```

### Dashboard Panel (Attacks Over Time)

```spl
index=security sourcetype="llm-soc-triage:idor_detection"
| timechart count by severity
| rename CRITICAL_IDOR_ATTACK as "Critical", ALERT_MEDIUM as "Medium", ALERT_LOW as "Low"
```

---

## Elastic Query (Elasticsearch / Kibana)

### Detection Query

```json
{
  "query": {
    "bool": {
      "must": [
        {
          "term": {
            "event_type": "idor_detection_event"
          }
        },
        {
          "terms": {
            "severity": ["CRITICAL_IDOR_ATTACK", "ALERT_MEDIUM"]
          }
        },
        {
          "range": {
            "distinct_resources_accessed": {
              "gte": 3
            }
          }
        },
        {
          "term": {
            "is_sequential": true
          }
        }
      ],
      "must_not": [
        {
          "terms": {
            "user_tags": ["qa_automation", "pentester"]
          }
        }
      ]
    }
  },
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ]
}
```

### Detection Rule (Kibana Security)

```yaml
name: "IDOR Enumeration Attack - Sequential Pattern"
description: "Detects sequential IDOR enumeration attacks from llm-soc-triage middleware"
risk_score: 90
severity: "critical"
rule_type: "query"
index:
  - "logs-security-*"
  - "logs-llm-soc-triage-*"
query: |
  event.module: "llm-soc-triage" AND
  event.category: "idor_detection" AND
  event.severity: ("CRITICAL_IDOR_ATTACK" OR "ALERT_MEDIUM") AND
  event.distinct_resources_accessed >= 3 AND
  event.is_sequential: true AND
  NOT event.user_tags: ("qa_automation" OR "pentester")
threat:
  - framework: "MITRE ATT&CK"
    tactic:
      id: "TA0009"
      name: "Collection"
      reference: "https://attack.mitre.org/tactics/TA0009/"
    technique:
      - id: "T1213"
        name: "Data from Information Repositories"
        reference: "https://attack.mitre.org/techniques/T1213/"
        subtechnique:
          - id: "T1213.002"
            name: "Sharepoint"
            reference: "https://attack.mitre.org/techniques/T1213/002/"
false_positives:
  - "QA testing with appropriate user tags"
  - "Internal penetration testing"
  - "Customer support multi-account access"
actions:
  - "Investigate user session and access history"
  - "Review failed_resources and resource_owners for pattern"
  - "Check for auto-hold action execution"
  - "Correlate with SOAR incident ticket"
```

---

## Chronicle YARA-L

```yaml
rule idor_sequential_enumeration {
  meta:
    author = "Agentic Security Partners LLC"
    description = "Detects IDOR enumeration attacks with ownership awareness"
    severity = "CRITICAL"
    mitre = "T1213.002"
    reference = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
  
  events:
    $e.metadata.product_name = "llm-soc-triage"
    $e.metadata.event_type = "idor_detection_event"
    $e.security_result.severity = "CRITICAL_IDOR_ATTACK"
    $e.extensions.distinct_resources_accessed >= 3
    $e.extensions.is_sequential = true
    not $e.principal.user.tags = /qa_automation|pentester/
  
  match:
    $user_id over 1h
  
  outcome:
    $risk_score = max(90)
    $mitre_attack_tactic = "TA0009"
    $mitre_attack_technique = "T1213.002"
    $alert_action = "auto_hold"
  
  condition:
    $e
}
```

---

## Sumo Logic

```sql
_sourceCategory=security/idor_detection
| where severity in ("CRITICAL_IDOR_ATTACK", "ALERT_MEDIUM")
| where distinct_resources_accessed >= 3
| where is_sequential = "true"
| where !(user_tags matches "*qa_automation*" OR user_tags matches "*pentester*")
| fields detection_timestamp, event_id, user_id, session_id, severity, distinct_resources_accessed, failed_resources, mitre_tactics, mitre_techniques
| sort by detection_timestamp desc
```

---

## Microsoft Sentinel (KQL)

```kql
SecurityEvents
| where ProductName == "llm-soc-triage"
| where EventType == "idor_detection_event"
| where Severity in ("CRITICAL_IDOR_ATTACK", "ALERT_MEDIUM")
| where DistinctResourcesAccessed >= 3
| where IsSequential == true
| where UserTags !contains "qa_automation" and UserTags !contains "pentester"
| extend MITRETactics = tostring(mitre_tactics)
| extend MITRETechniques = tostring(mitre_techniques)
| project TimeGenerated, EventID, UserID, SessionID, Severity, DistinctResourcesAccessed, FailedResources, ResourceOwners, MITRETactics, MITRETechniques
| sort by TimeGenerated desc
```

### Sentinel Analytic Rule

```yaml
name: IDOR Enumeration Attack Detection
description: |
  Detects sequential IDOR enumeration attacks using ownership-aware logic
  from llm-soc-triage middleware. High confidence attacks trigger auto-hold.
severity: High
tactics:
  - Collection
  - CredentialAccess
relevantTechniques:
  - T1213
  - T1213.002
  - T1078.004
query: |
  SecurityEvents
  | where ProductName == "llm-soc-triage"
  | where EventType == "idor_detection_event"
  | where Severity == "CRITICAL_IDOR_ATTACK"
  | where DistinctResourcesAccessed >= 3
  | where IsSequential == true
  | where UserTags !contains "qa_automation"
  | extend AccountCustomEntity = UserID
  | extend IPCustomEntity = ClientIP
queryFrequency: 5m
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
suppressionDuration: 5h
```

---

## QRadar AQL

```sql
SELECT
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') as detection_time,
    UTF8(payload) as event_data,
    "event_id",
    "user_id",
    "session_id",
    "severity",
    "distinct_resources_accessed",
    "failed_resources",
    "mitre_tactics"
FROM events
WHERE 
    "sourcetype" = 'llm-soc-triage:idor_detection'
    AND "severity" IN ('CRITICAL_IDOR_ATTACK', 'ALERT_MEDIUM')
    AND "distinct_resources_accessed" >= 3
    AND "is_sequential" = 'true'
    AND NOT ("user_tags" ILIKE '%qa_automation%' OR "user_tags" ILIKE '%pentester%')
ORDER BY starttime DESC
LAST 24 HOURS
```

---

## Integration Guide

### Log Forwarding from Middleware

Configure the middleware to forward detection events to your SIEM:

```python
# In core/detection_middleware.py
import logging
import logging.handlers

# Configure syslog forwarding to SIEM
siem_handler = logging.handlers.SysLogHandler(
    address=('siem.company.com', 514),  # SIEM syslog endpoint
    facility=logging.handlers.SysLogHandler.LOG_LOCAL0
)

siem_handler.setFormatter(logging.Formatter(
    '%(asctime)s llm-soc-triage idor_detection: %(message)s'
))

logger.addHandler(siem_handler)
```

### JSON Event Format

All IDOR detection events follow this standardized structure for SIEM ingestion:

```json
{
  "timestamp": "2026-01-27T14:32:15.123Z",
  "source": "llm-soc-triage",
  "sourcetype": "idor_detection",
  "event_type": "idor_detection_event",
  "event_id": "idor_evt_20260127_143215_abc123",
  "severity": "CRITICAL_IDOR_ATTACK",
  "user_id": "usr_a8f3c2d1",
  "session_id": "sess_9d4e2a1f",
  "distinct_resources_accessed": 4,
  "is_sequential": true,
  "time_window_seconds": 45,
  "failed_resources": ["loan_4395669", "loan_4395670", "loan_4395671", "loan_4395672"],
  "resource_owners": ["usr_b9e4d3c2", "usr_c0f5e4d3", "usr_d1g6f5e4", "usr_e2h7g6f5"],
  "mitre_tactics": ["TA0009"],
  "mitre_techniques": ["T1213"],
  "mitre_sub_techniques": ["T1213.002"],
  "mitre_attack_urls": [
    "https://attack.mitre.org/techniques/T1213/",
    "https://attack.mitre.org/techniques/T1213/002/"
  ],
  "user_email": "[EMAIL_REDACTED]",
  "client_ip": "[IP_REDACTED]",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "auto_hold_triggered": true
}
```

---

## Threat Hunting Queries

### Find Users with Repeated IDOR Attempts

**Splunk**:
```spl
index=security sourcetype="llm-soc-triage:idor_detection"
| stats count as attack_count, values(session_id) as sessions, values(failed_resources) as targeted_loans by user_id
| where attack_count > 1
| sort -attack_count
```

**Elastic**:
```json
{
  "query": {
    "term": {"event_type": "idor_detection_event"}
  },
  "aggs": {
    "users": {
      "terms": {"field": "user_id"},
      "aggs": {
        "attack_count": {"value_count": {"field": "event_id"}},
        "sessions": {"terms": {"field": "session_id"}},
        "targeted_loans": {"terms": {"field": "failed_resources"}}
      }
    }
  }
}
```

### Identify Most Targeted Resource Owners

**Splunk**:
```spl
index=security sourcetype="llm-soc-triage:idor_detection" severity="CRITICAL_IDOR_ATTACK"
| mvexpand resource_owners
| stats count as times_targeted, values(user_id) as attackers by resource_owners
| sort -times_targeted
| head 20
```

### Correlate with WAF/CDN Logs

**Splunk**:
```spl
index=security
    (sourcetype="llm-soc-triage:idor_detection" severity="CRITICAL_IDOR_ATTACK")
    OR (sourcetype="cloudflare:firewall" action="block")
| transaction session_id maxspan=5m
| where eventcount > 1
| table _time user_id session_id client_ip user_agent sourcetype action
```

---

## SOAR Playbook Triggers

### Splunk SOAR (Phantom) Action

```python
# Phantom Playbook: IDOR Auto-Response
def on_idor_critical(container):
    """
    Triggered when CRITICAL_IDOR_ATTACK event received from llm-soc-triage
    """
    event_data = container['data'][0]
    
    # Extract key fields
    user_id = event_data['user_id']
    session_id = event_data['session_id']
    failed_resources = event_data['failed_resources']
    mitre_techniques = event_data['mitre_techniques']
    
    # Action 1: Auto-hold user account
    phantom.act("disable user", parameters={
        "user_id": user_id,
        "reason": f"IDOR attack detected: {len(failed_resources)} unauthorized access attempts"
    })
    
    # Action 2: Notify SOC team
    phantom.act("send email", parameters={
        "to": "soc-team@company.com",
        "subject": f"CRITICAL: IDOR Attack by {user_id}",
        "body": f"Session {session_id} attempted enumeration of {len(failed_resources)} loans. Auto-hold executed. MITRE: {mitre_techniques}"
    })
    
    # Action 3: Enrich with threat intel
    phantom.act("lookup ip", parameters={
        "ip": event_data['client_ip']
    })
    
    return
```

---

## Datadog Log Monitor

### Detection Monitor

```yaml
name: "IDOR Enumeration Attack - Critical"
type: "log alert"
query: |
  source:llm-soc-triage service:idor_detection 
  @severity:(CRITICAL_IDOR_ATTACK OR ALERT_MEDIUM) 
  @distinct_resources_accessed:>=3 
  @is_sequential:true 
  -@user_tags:(qa_automation OR pentester)
message: |
  IDOR enumeration attack detected
  
  User: {{@user_id}}
  Session: {{@session_id}}
  Resources Attempted: {{@distinct_resources_accessed}}
  Sequential: {{@is_sequential}}
  Time Window: {{@time_window_seconds}}s
  MITRE: {{@mitre_techniques}}
  
  Failed Resources: {{@failed_resources}}
  Resource Owners: {{@resource_owners}}
  
  Auto-hold triggered: {{@auto_hold_triggered}}
tags:
  - security:attack
  - mitre:t1213
  - owasp:a01
priority: "1"
renotify_interval: 0
notify_no_data: false
notification_preset_name: "hide_all"
```

---

## Custom Webhook Integration

For SIEMs without native log ingestion, use webhook forwarding:

```python
# In core/detection_middleware.py
import httpx

async def forward_to_siem(event: IDORDetectionEvent):
    """Forward detection event to SIEM webhook"""
    siem_webhook = os.getenv("SIEM_WEBHOOK_URL")
    
    payload = {
        "timestamp": event.detection_timestamp.isoformat(),
        "source": "llm-soc-triage",
        "sourcetype": "idor_detection",
        "event": event.model_dump(),
    }
    
    async with httpx.AsyncClient() as client:
        await client.post(
            siem_webhook,
            json=payload,
            headers={"Authorization": f"Bearer {os.getenv('SIEM_API_KEY')}"},
            timeout=5.0
        )
```

---

## Alert Thresholds and Tuning

### Recommended Baselines

| Environment | Threshold | Window | Sequential Gap | FP Rate |
|-------------|-----------|--------|----------------|---------|
| Production | 3 distinct resources | 60s | ≤10 | <2% |
| High Traffic | 5 distinct resources | 120s | ≤10 | <1% |
| Dev/Staging | 5 distinct resources | 300s | ≤20 | <5% |

### Tuning Guide

1. **Week 1-2**: Deploy in shadow mode, collect baseline metrics
2. **Week 3-4**: Analyze false positive rate, adjust threshold if >5%
3. **Month 2**: Enable alerting, monitor analyst feedback
4. **Month 3+**: Fine-tune sequential gap based on application ID schema

**Adjustment Scenarios**:
- **High FP rate (>5%)**: Increase threshold to 4-5 or extend window to 120s
- **Low detection rate (<90%)**: Decrease threshold to 2 or tighten window to 30s
- **Sequential FPs**: Increase sequential gap threshold (if IDs naturally have gaps)

---

## Integration with Existing SOAR

### ServiceNow Security Incident

```json
POST /api/now/table/sn_si_incident
{
  "short_description": "IDOR Attack: {{event.user_id}} - {{event.distinct_resources_accessed}} resources",
  "description": "Sequential IDOR enumeration detected by llm-soc-triage middleware.\n\nUser: {{event.user_id}}\nSession: {{event.session_id}}\nAttack Vector: {{event.mitre_techniques}}\nFailed Resources: {{event.failed_resources}}\nTime Window: {{event.time_window_seconds}}s",
  "severity": "1",
  "urgency": "1",
  "category": "Security",
  "subcategory": "Access Control",
  "assigned_to": "soc_tier2",
  "cmdb_ci": "webapp_loan_application",
  "impact": "1",
  "state": "2",
  "work_notes": "Auto-hold triggered: {{event.auto_hold_triggered}}"
}
```

### Palo Alto XSOAR Incident

```json
{
  "name": "IDOR Enumeration Attack - {{event.user_id}}",
  "type": "Access Control - IDOR",
  "severity": 4,
  "details": "{{event}}",
  "labels": [
    {"type": "MITRE_Tactic", "value": "TA0009"},
    {"type": "MITRE_Technique", "value": "T1213.002"},
    {"type": "User", "value": "{{event.user_id}}"},
    {"type": "Session", "value": "{{event.session_id}}"}
  ],
  "customFields": {
    "distinctresources": {{event.distinct_resources_accessed}},
    "issequential": {{event.is_sequential}},
    "timewindow": {{event.time_window_seconds}},
    "autoholdtriggered": {{event.auto_hold_triggered}}
  }
}
```

---

## References

- **MITRE ATT&CK**: [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- **OWASP**: [A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- **Sigma**: [Rule Repository](https://github.com/SigmaHQ/sigma)
- **Chronicle YARA-L**: [Detection Engineering Guide](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview)
