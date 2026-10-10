# Network Behavior Security Knowledge

## Overview

Network behavior describes patterns of communication observed between
hosts and services.

A behavior is not inherently malicious. Its security significance depends
on context, frequency, timing, destination, protocol, and related evidence.

## High Connection Volume

A host generating an unusually large number of connections may indicate:

- Service discovery
- Network scanning
- Automated applications
- Monitoring activity
- Misconfiguration
- Potential reconnaissance

High connection volume alone is not sufficient to confirm malicious activity.

## Failed Connections

A high number of failed connections can be associated with:

- Incorrect configuration
- Unavailable services
- Network problems
- Port scanning
- Repeated connection attempts

The destination ports, destinations, frequency, and historical behavior
should be considered when interpreting failed connections.

## Repeated Connections

Repeated connections between the same hosts may represent:

- Normal application traffic
- Monitoring
- Periodic service communication
- Automated processes
- Persistent or repeated suspicious activity

The expected baseline for the host and service should be considered.

## Unusual Destination Ports

Communication with an unusual destination port may require investigation.

Possible explanations include:

- Legitimate application services
- Administrative services
- Custom applications
- Temporary services
- Misconfiguration
- Potential command-and-control activity

The port number alone does not establish malicious intent.

## Large Data Transfers

Large amounts of transferred data may result from:

- File transfers
- Backups
- Software updates
- Streaming
- Database operations
- Normal application traffic
- Potential data exfiltration

Data volume should be interpreted together with the destination,
protocol, timing, and host behavior.

## AnomalySpike Context

AnomalySpike can combine behavioral evidence with:

- Zeek telemetry
- Suricata alerts
- Machine-learning anomaly scores
- Host profiles
- Host timelines
- MITRE ATT&CK knowledge

The purpose of the knowledge base is to provide context for observed
evidence, not to automatically classify every unusual behavior as malicious.
