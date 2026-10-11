import os
from collections import defaultdict
from statistics import mean

import joblib
import numpy as np
from opensearchpy import OpenSearch

from backend.app.detection.baseline import (
    FEATURE_NAMES,
    evaluate_window,
)


OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

FEATURES_INDEX = "anomalyspike-features"
ANOMALIES_INDEX = "anomalyspike-anomalies"
STATE_INDEX = "anomalyspike-state"
STATE_ID = "hybrid-detection"

MODEL_PATH = "backend/app/models/isolation_forest.pkl"

MODEL_VERSION = "0.4.0"

MINIMUM_BASELINE_WINDOWS = 3


client = OpenSearch(
    hosts=[
        {
            "host": OPENSEARCH_HOST,
            "port": OPENSEARCH_PORT,
        }
    ]
)


def get_features():
    response = client.search(
        index=FEATURES_INDEX,
        body={
            "size": 10000,
            "query": {
                "match_all": {}
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "asc"
                    }
                }
            ]
        }
    )

    return [
        {
            "id": hit["_id"],
            "data": hit["_source"],
        }
        for hit in response["hits"]["hits"]
    ]


def load_ml_model():
    print("[HYBRID] Loading ML model...")

    package = joblib.load(MODEL_PATH)

    model = package["model"]
    feature_names = package["feature_names"]

    transform = package.get(
        "transform",
        "none"
    )

    version = package.get(
        "version",
        "unknown"
    )

    print(
        f"[HYBRID] ML model version: {version}"
    )

    print(
        f"[HYBRID] Transformation: {transform}"
    )

    return (
        model,
        feature_names,
        transform,
        version,
    )


def build_matrix(
    records,
    feature_names,
    transform,
):
    matrix = []

    for record in records:
        features = record["data"].get(
            "features",
            {}
        )

        matrix.append(
            [
                features.get(
                    name,
                    0
                )
                for name in feature_names
            ]
        )

    matrix = np.asarray(
        matrix,
        dtype=float,
    )

    if transform == "log1p":
        matrix = np.log1p(matrix)

    return matrix


def score_ml(
    model,
    records,
    feature_names,
    transform,
):
    if not records:
        return [], []

    matrix = build_matrix(
        records,
        feature_names,
        transform,
    )

    scores = model.decision_function(
        matrix
    )

    predictions = model.predict(
        matrix
    )

    return scores, predictions


def get_state():
    try:
        response = client.get(
            index=STATE_INDEX,
            id=STATE_ID,
        )

        return response["_source"]

    except Exception:
        return None


def save_state(
    last_timestamp,
    baselines,
):
    client.index(
        index=STATE_INDEX,
        id=STATE_ID,
        body={
            "last_processed_timestamp": last_timestamp,
            "baseline": baselines,
            "version": MODEL_VERSION,
            "minimum_baseline_windows": MINIMUM_BASELINE_WINDOWS,
        }
    )


def build_initial_baseline(records):
    """
    Build the initial historical baseline.

    Existing feature windows are treated as history only.
    They are NOT evaluated as new anomalies.
    """

    hosts = defaultdict(list)

    for record in records:
        data = record["data"]

        source_ip = (
            data.get("source", {})
            .get("ip")
        )

        if not source_ip:
            continue

        hosts[source_ip].append(
            data.get("features", {})
        )

    baselines = {}

    for host, windows in hosts.items():

        if len(windows) < MINIMUM_BASELINE_WINDOWS:
            baselines[host] = {
                "status": "insufficient_data",
                "window_count": len(windows),
                "features": {},
            }
            continue

        feature_stats = {}

        for feature in FEATURE_NAMES:
            values = [
                float(
                    window.get(
                        feature,
                        0
                    )
                )
                for window in windows
            ]

            feature_stats[feature] = {
                "min": min(values),
                "max": max(values),
                "mean": mean(values),
            }

        baselines[host] = {
            "status": "ready",
            "window_count": len(windows),
            "features": feature_stats,
        }

    return baselines


def baseline_for_record(
    baselines,
    record,
):
    data = record["data"]

    source_ip = (
        data.get("source", {})
        .get("ip")
    )

    return evaluate_window(
        source_ip,
        data.get("features", {}),
        baselines,
    )


def update_baseline(baselines, record):
    data = record["data"]
    source_ip = data["source"]["ip"]
    features = data["features"]

    if source_ip not in baselines:
        baselines[source_ip] = {
            "status": "insufficient_data",
            "window_count": 0,
            "features": {},
        }

    baseline = baselines[source_ip]
    feature_stats = baseline.setdefault("features", {})
    current_count = baseline.get("window_count", 0)

    # Older buggy state may have a count but no statistics.
    # Its earlier observations cannot be recovered from this state.
    if current_count > 0 and not feature_stats:
        current_count = 0
        baseline["window_count"] = 0

    new_count = current_count + 1

    for name in FEATURE_NAMES:
        value = float(features.get(name, 0))

        if name not in feature_stats:
            feature_stats[name] = {
                "min": value,
                "max": value,
                "mean": value,
            }
        else:
            stats = feature_stats[name]
            old_mean = float(stats["mean"])

            stats["mean"] = (
                old_mean * current_count + value
            ) / new_count

            stats["min"] = min(float(stats["min"]), value)
            stats["max"] = max(float(stats["max"]), value)

    baseline["window_count"] = new_count
    baseline["status"] = (
        "ready"
        if new_count >= MINIMUM_BASELINE_WINDOWS
        else "insufficient_data"
    )


def create_result(
    record,
    behavioral,
    ml_score,
    ml_prediction,
    model_version,
):
    data = record["data"]

    behavioral_score = float(
        behavioral["score"]
    )

    ml_anomaly = (
        int(ml_prediction) == 1
    )

    behavioral_anomaly = (
        behavioral_score > 0
    )

    # Preserve both detector signals.
    #
    # We do not create a weighted score here.
    # A future decision layer can distinguish
    # ML-only outliers from corroborated
    # behavioral anomalies.

    is_anomaly = (
        ml_anomaly
        or behavioral_anomaly
    )

    return {
        "@timestamp": data.get(
            "@timestamp"
        ),

        "event": {
            "source": "anomalyspike",
            "type": "anomaly_detection",
        },

        "source": data.get(
            "source",
            {}
        ),

        "features": data.get(
            "features",
            {}
        ),

        "anomaly": {
            "is_anomaly": is_anomaly,

            "behavioral_score":
                behavioral_score,

            "ml_score":
                float(ml_score),

            "ml_prediction":
                int(ml_prediction),

            "model": "hybrid",

            "version": model_version,
        },

        "detection": {
            "behavioral_status":
                behavioral["status"],

            "behavioral_anomaly":
                behavioral_anomaly,

            "ml_anomaly":
                ml_anomaly,

            "evidence":
                behavioral["evidence"],
        },

        "anomalyspike": {
            "sensor": "sensor-01",
            "pipeline": "temporal-hybrid-detection",
        },
    }


def store_result(
    record,
    result,
):
    data = record["data"]

    source_ip = (
        data.get("source", {})
        .get("ip", "unknown")
    )

    timestamp = data.get(
        "@timestamp",
        "unknown"
    )

    document_id = (
        f"{source_ip}-{timestamp}"
    )

    client.index(
        index=ANOMALIES_INDEX,
        id=document_id,
        body=result,
    )

    print(
        f"[HYBRID] Stored {document_id}"
    )


def run():
    print(
        "[HYBRID] Loading feature windows..."
    )

    records = get_features()

    print(
        f"[HYBRID] Loaded {len(records)} "
        "feature windows"
    )

    if not records:
        print(
            "[HYBRID] No feature data found."
        )
        return

    (
        model,
        feature_names,
        transform,
        model_version,
    ) = load_ml_model()

    state = get_state()

    # --------------------------------------------------
    # FIRST RUN
    # --------------------------------------------------

    if not state:

        print(
            "[HYBRID] No temporal state found."
        )

        print(
            "[HYBRID] Initializing historical "
            "baseline from existing windows..."
        )

        baselines = build_initial_baseline(
            records
        )

        ready_hosts = sum(
            1
            for baseline in baselines.values()
            if baseline["status"] == "ready"
        )

        print(
            f"[HYBRID] Hosts with ready baselines: "
            f"{ready_hosts}/{len(baselines)}"
        )

        newest_timestamp = (
            records[-1]["data"]["@timestamp"]
        )

        save_state(
            newest_timestamp,
            baselines,
        )

        print(
            "[HYBRID] Historical baseline initialized."
        )

        print(
            f"[HYBRID] Last processed timestamp: "
            f"{newest_timestamp}"
        )

        print(
            "[HYBRID] Existing windows were NOT "
            "classified as anomalies."
        )

        return

    # --------------------------------------------------
    # EXISTING STATE
    # --------------------------------------------------

    last_timestamp = state.get(
        "last_processed_timestamp"
    )

    baselines = state.get(
        "baseline",
        {}
    )

    print(
        "[HYBRID] Existing temporal state found."
    )

    print(
        f"[HYBRID] Last processed timestamp: "
        f"{last_timestamp}"
    )

    # Only process windows that arrived
    # after the previous state.

    new_records = [
        record
        for record in records
        if record["data"].get(
            "@timestamp"
        ) > last_timestamp
    ]

    if not new_records:

        print(
            "[HYBRID] No new feature windows."
        )

        return

    print(
        f"[HYBRID] New feature windows: "
        f"{len(new_records)}"
    )

    # --------------------------------------------------
    # ML SCORING
    # --------------------------------------------------

    ml_scores, ml_predictions = score_ml(
        model,
        new_records,
        feature_names,
        transform,
    )

    # --------------------------------------------------
    # TEMPORAL HYBRID DETECTION
    # --------------------------------------------------

    anomalies = 0
    behavioral_signals = 0
    ml_signals = 0

    for (
        record,
        ml_score,
        ml_prediction,
    ) in zip(
        new_records,
        ml_scores,
        ml_predictions,
    ):

        # IMPORTANT:
        # evaluate BEFORE updating baseline.

        behavioral = baseline_for_record(
            baselines,
            record,
        )

        result = create_result(
            record,
            behavioral,
            ml_score,
            ml_prediction,
            model_version,
        )

        store_result(
            record,
            result,
        )

        if result["anomaly"]["is_anomaly"]:
            anomalies += 1

        if result["detection"]["behavioral_anomaly"]:
            behavioral_signals += 1

        if result["detection"]["ml_anomaly"]:
            ml_signals += 1

        # IMPORTANT:
        # update baseline only AFTER detection.

        update_baseline(
            baselines,
            record,
        )

    newest_timestamp = (
        new_records[-1]["data"]["@timestamp"]
    )

    save_state(
        newest_timestamp,
        baselines,
    )

    print(
        "[HYBRID] Detection completed."
    )

    print(
        f"[HYBRID] Analyzed: "
        f"{len(new_records)} windows"
    )

    print(
        f"[HYBRID] Hybrid signals: "
        f"{anomalies}"
    )

    print(
        f"[HYBRID] Behavioral signals: "
        f"{behavioral_signals}"
    )

    print(
        f"[HYBRID] ML signals: "
        f"{ml_signals}"
    )

    print(
        "[HYBRID] Temporal state updated."
    )


if __name__ == "__main__":
    run()
