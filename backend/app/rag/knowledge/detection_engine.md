# AnomalyStrike Hybrid Detection Engine

## Overview

AnomalyStrike scores host behavior every minute using two independent
detectors: a behavioral baseline detector and a machine learning
(Isolation Forest) model. Their outputs are combined into a single
hybrid result.

## Behavioral detection

The behavioral detector builds a running per-host baseline (minimum,
maximum, and mean) for six features: DNS query count, connection
count, unique destination count, bytes sent, bytes received, and
failed connection count.

A behavioral anomaly is flagged when a feature exceeds the host's
historical maximum, falls below its historical minimum, or
represents entirely new activity for that host (for example, the
first time a host sends any data at all). The behavioral score
reflects how far the observation deviates from the baseline.

A host needs at least three historical observations before it
receives a behavioral score; before that, its status is
"insufficient_data" and it cannot be behaviorally flagged.

## ML detection

The ML detector uses an Isolation Forest model trained on recent
historical feature windows across all hosts. Unlike the behavioral
detector, it is not per-host — it learns what a typical window looks
like across the whole network and flags windows that appear
statistically unusual relative to that general pattern.

The ML model's decision score can be positive (flagged as anomalous)
or negative (considered normal). A score close to zero on either
side of the boundary indicates a borderline case — the observation
sits near the edge of what the model considers typical, rather than
being a clear outlier.

## Combining the two signals

A window is marked as an overall anomaly (`is_anomaly: true`) if
EITHER the behavioral detector OR the ML detector flags it. The two
signals are reported separately (`behavioral_anomaly`,
`ml_anomaly`) so an analyst can see whether a flagged window is
corroborated by both detectors or driven by only one.

A window flagged by the ML detector alone, with a low positive
score and no behavioral corroboration, is a weaker signal than one
where both detectors agree. This pattern is common for borderline
or self-generated traffic (for example, a host's own monitoring or
dashboard polling) rather than genuinely novel or malicious activity.

## Interpreting a flagged anomaly

When reviewing a flagged window, useful questions include:

- Did both detectors agree, or only one?
- How far from zero is the ML score — clearly anomalous, or
  borderline?
- Does the behavioral evidence point to a specific feature (for
  example, an unusual number of failed connections), or is the
  behavioral score zero?
- Is the host's baseline status "ready", or was it still building
  up historical data?
