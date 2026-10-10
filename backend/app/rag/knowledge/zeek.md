# Zeek Security Knowledge

## Overview

Zeek is a network security monitor that produces detailed network
telemetry and protocol metadata.

AnomalySpike uses Zeek as a primary source of network activity evidence.

## Connection Events

Zeek connection records describe network communication between hosts.

Important fields include:

- source.ip: Source host IP address.
- source.port: Source network port.
- destination.ip: Destination host IP address.
- destination.port: Destination network port.
- network.transport: Transport protocol such as TCP or UDP.
- network.protocol: Detected application or network protocol.
- zeek.uid: Unique identifier for the Zeek connection.
- duration: Duration of the connection.
- orig_bytes: Bytes sent by the originator.
- resp_bytes: Bytes sent by the responder.
- conn_state: Connection state.
- history: Connection activity history.

## Interpreting Zeek Data

A single Zeek connection does not necessarily indicate malicious activity.

Security analysis should consider:

- Frequency of connections
- Destination hosts
- Destination ports
- Connection states
- Data volume
- Protocols
- Historical behavior
- Related Suricata alerts
- Machine-learning anomaly results

## AnomalySpike Context

AnomalySpike uses Zeek connection data to provide network activity
evidence during host investigations.

Zeek telemetry can be correlated with Suricata alerts and anomaly
detection results to provide additional context about suspicious behavior.
