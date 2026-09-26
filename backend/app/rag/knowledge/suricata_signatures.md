# Suricata Signature Categories

## Overview

Suricata alerts are grouped by category and severity. Understanding
what a signature category means helps distinguish routine background
noise from activity that warrants investigation.

## ET INFO

Signatures in the "ET INFO" category are informational. They flag
traffic that is notable but not inherently malicious — for example,
a Linux package manager's user-agent string appearing in outbound
HTTP traffic, or a connection to a known file-hosting service.

ET INFO alerts are expected on a normally functioning host and do
not by themselves indicate compromise.

## GPL ATTACK_RESPONSE

This category flags responses that resemble command output typically
associated with a successful exploit (for example, output that looks
like the result of a privilege check). A single GPL ATTACK_RESPONSE
alert triggered by a known benign test endpoint (such as a
self-test service) is expected and not evidence of compromise.

The same signature triggered by an unexpected, unrecognized, or
external destination is more concerning and should be investigated
by reviewing the destination IP, the full connection context, and
whether the host initiated the connection intentionally.

## ET HUNTING

"Hunting" signatures are broader and more speculative than other
categories. They are designed to surface potentially interesting
traffic for a human analyst to review, not to make a final
determination. A HUNTING alert alone is a prompt for investigation,
not a conclusion.

## Severity levels

Suricata assigns a numeric severity (commonly 1-3, where lower
numbers indicate higher severity in many rulesets). Severity should
be read alongside category: a low-severity ET INFO alert is routine,
while a low-severity-number alert in a category like
ATTACK_RESPONSE or TROJAN warrants closer attention.

## Investigating a Suricata alert

When reviewing a Suricata alert, useful context includes:

- The signature category and what it is designed to detect
- Whether the destination is a known, expected service
- Whether the source host has triggered this signature before
- Whether other signals (Zeek connection data, ML/behavioral
  anomalies) corroborate the alert
- Whether the traffic was initiated by the host or received from
  elsewhere

A single alert in isolation is a starting point for investigation,
not a verdict.
