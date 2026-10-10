# Suricata Security Knowledge

## Overview

Suricata is a network threat detection engine capable of intrusion detection,
intrusion prevention, network security monitoring, and protocol analysis.

AnomalySpike uses Suricata alerts as one source of security evidence.

## Suricata Alerts

A Suricata alert is generated when network traffic matches a detection rule.

Important alert fields include:

- signature_id: Unique identifier of the detection signature.
- signature: Name or description of the triggered rule.
- category: Classification of the detected activity.
- severity: Severity assigned to the alert.
- action: Action associated with the detection.
- protocol: Network protocol involved.

## Interpreting Alerts

A Suricata alert should be treated as security evidence rather than
automatically interpreted as a confirmed compromise.

The alert should be evaluated together with:

- Source IP
- Destination IP
- Destination port
- Network protocol
- Alert signature
- Severity
- Related network events
- Host behavior over time

## AnomalySpike Context

AnomalySpike can correlate Suricata alerts with Zeek network events and
machine-learning anomaly detection results.

This allows an investigation to combine signature-based detection with
behavioral evidence.
