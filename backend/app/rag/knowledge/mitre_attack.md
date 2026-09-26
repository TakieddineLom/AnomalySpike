# MITRE ATT&CK Security Knowledge

## Overview

MITRE ATT&CK is a knowledge base that describes adversary tactics,
techniques, and procedures observed in real-world cyber operations.

AnomalyStrike can use ATT&CK concepts to provide security context for
observed network behaviors.

## Tactics

Tactics describe the adversary's high-level objective.

Examples include:

- Reconnaissance
- Resource Development
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

## Techniques

Techniques describe methods that adversaries may use to achieve a tactic.

A network behavior should not automatically be mapped to a technique
without sufficient evidence.

ATT&CK mappings should therefore be treated as contextual hypotheses
supported by observed evidence.

## AnomalyStrike Context

AnomalyStrike can combine:

- Zeek network telemetry
- Suricata alerts
- Machine-learning anomalies
- Host timelines
- Host profiles

with ATT&CK knowledge to provide additional context during security
investigations.

ATT&CK information should help explain what a behavior may correspond to,
while the actual network evidence remains the basis of the investigation.
