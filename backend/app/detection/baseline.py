from collections import defaultdict
from statistics import mean


FEATURE_NAMES = [
    "dns_query_count",
    "connection_count",
    "unique_destination_count",
    "bytes_sent",
    "bytes_received",
    "failed_connection_count",
]


def load_baseline(events, minimum_windows=3):
    """
    Build a behavioral baseline for each host.

    A host needs at least minimum_windows historical
    observations before it receives a behavioral score.
    """

    hosts = defaultdict(list)

    for event in events:
        source_ip = event.get("source", {}).get("ip")

        if not source_ip:
            continue

        hosts[source_ip].append(
            event.get("features", {})
        )

    baselines = {}

    for host, windows in hosts.items():

        if len(windows) < minimum_windows:
            baselines[host] = {
                "status": "insufficient_data",
                "window_count": len(windows),
                "features": {}
            }
            continue

        feature_stats = {}

        for feature in FEATURE_NAMES:

            values = [
                float(window.get(feature, 0))
                for window in windows
            ]

            feature_stats[feature] = {
                "min": min(values),
                "max": max(values),
                "mean": mean(values)
            }

        baselines[host] = {
            "status": "ready",
            "window_count": len(windows),
            "features": feature_stats
        }

    return baselines


def evaluate_window(host, features, baseline):

    host_baseline = baseline.get(host)

    if not host_baseline:
        return {
            "status": "insufficient_data",
            "score": 0.0,
            "evidence": []
        }

    if host_baseline["status"] != "ready":
        return {
            "status": "insufficient_data",
            "score": 0.0,
            "evidence": []
        }

    evidence = []
    deviations = []

    for feature in FEATURE_NAMES:

        current = float(features.get(feature, 0))

        stats = host_baseline["features"][feature]

        minimum = stats["min"]
        maximum = stats["max"]
        average = stats["mean"]

        # Previously unseen positive activity.
        if maximum == 0 and current > 0:

            evidence.append({
                "feature": feature,
                "current": current,
                "baseline_max": 0,
                "baseline_mean": average,
                "ratio_to_max": None,
                "direction": "new_activity"
            })

            deviations.append(1.0)

            continue

        # Activity above historical maximum.
        if current > maximum and maximum > 0:

            ratio = current / maximum

            deviations.append(
                min(ratio - 1.0, 10.0)
            )

            evidence.append({
                "feature": feature,
                "current": current,
                "baseline_max": int(maximum),
                "baseline_mean": average,
                "ratio_to_max": ratio,
                "direction": "above_baseline"
            })

        # Activity below a non-zero historical minimum.
        elif current < minimum and minimum > 0:

            ratio = minimum / max(current, 0.001)

            deviations.append(
                min(ratio - 1.0, 10.0)
            )

            evidence.append({
                "feature": feature,
                "current": current,
                "baseline_min": int(minimum),
                "baseline_mean": average,
                "ratio_to_min": ratio,
                "direction": "below_baseline"
            })

    if not deviations:
        score = 0.0
    else:
        score = min(
            mean(deviations) / 10.0,
            1.0
        )

    return {
        "status": "ready",
        "score": score,
        "evidence": evidence
    }
