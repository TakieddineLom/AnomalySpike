import os

import joblib
import numpy as np
from opensearchpy import OpenSearch
from pyod.models.iforest import IForest


OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

FEATURES_INDEX = "anomalyspike-features"
MODEL_PATH = "backend/app/models/isolation_forest.pkl"

FEATURE_NAMES = [
    "dns_query_count",
    "connection_count",
    "unique_destination_count",
    "bytes_sent",
    "bytes_received",
    "failed_connection_count",
]


def get_features():
    client = OpenSearch(
        hosts=[{
            "host": OPENSEARCH_HOST,
            "port": OPENSEARCH_PORT
        }]
    )

    response = client.search(
        index=FEATURES_INDEX,
        body={
            "size": 1000,
            "query": {
                "match_all": {}
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
    )

    return [
        hit["_source"]["features"]
        for hit in response["hits"]["hits"]
    ]


def build_matrix(feature_docs):
    matrix = []

    for features in feature_docs:
        matrix.append([
            features.get(name, 0)
            for name in FEATURE_NAMES
        ])

    return np.asarray(matrix, dtype=float)


def transform_features(matrix):
    """
    Compress highly skewed count/byte features.

    log1p(x) = log(1 + x)

    This preserves zero values while reducing the influence
    of very large byte/count values.
    """
    return np.log1p(matrix)


def train():
    print("[TRAINING] Loading feature windows...")

    feature_docs = get_features()

    if len(feature_docs) < 10:
        raise RuntimeError(
            f"Need at least 10 feature windows, found {len(feature_docs)}"
        )

    print(f"[TRAINING] Loaded {len(feature_docs)} feature windows")

    X_raw = build_matrix(feature_docs)

    print(f"[TRAINING] Raw training matrix: {X_raw.shape}")

    X = transform_features(X_raw)

    print(f"[TRAINING] Transformed training matrix: {X.shape}")

    model = IForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )

    model.fit(X)

    package = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "transform": "log1p",
        "version": "0.2.0",
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    joblib.dump(package, MODEL_PATH)

    print(f"[TRAINING] Model saved to: {MODEL_PATH}")
    print("[TRAINING] Model version: 0.2.0")
    print("[TRAINING] Feature transformation: log1p")


if __name__ == "__main__":
    train()
