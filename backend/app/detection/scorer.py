import os

import joblib
import numpy as np

from opensearchpy import OpenSearch


MODEL_PATH = "backend/app/models/isolation_forest.pkl"

OPENSEARCH_HOST = os.getenv(
    "OPENSEARCH_HOST",
    "localhost"
)

OPENSEARCH_PORT = int(
    os.getenv(
        "OPENSEARCH_PORT",
        "9200"
    )
)

FEATURES_INDEX = "anomalyspike-features"
ANOMALIES_INDEX = "anomalyspike-anomalies"
STATE_INDEX = "anomalyspike-state"
STATE_ID = "ml-scoring"


client = OpenSearch(
    hosts=[
        {
            "host": OPENSEARCH_HOST,
            "port": OPENSEARCH_PORT
        }
    ]
)


def load_model():

    print("[SCORER] Loading model...")

    package = joblib.load(
        MODEL_PATH
    )

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
        f"[SCORER] Model loaded "
        f"({len(feature_names)} features)"
    )

    print(
        f"[SCORER] Model version: {version}"
    )

    print(
        f"[SCORER] Feature transformation: "
        f"{transform}"
    )

    return (
        model,
        feature_names,
        transform,
        version
    )


def get_last_scored_timestamp():

    try:

        response = client.get(
            index=STATE_INDEX,
            id=STATE_ID
        )

        return response["_source"].get(
            "last_scored_timestamp"
        )

    except Exception:

        return None


def get_new_features(last_timestamp=None):

    query = {
        "bool": {
            "must": [
                {
                    "match_all": {}
                }
            ]
        }
    }

    if last_timestamp:

        query["bool"]["filter"] = [
            {
                "range": {
                    "@timestamp": {
                        "gt": last_timestamp
                    }
                }
            }
        ]

    response = client.search(
        index=FEATURES_INDEX,
        body={
            "size": 1000,
            "query": query,
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
            "data": hit["_source"]
        }
        for hit in response["hits"]["hits"]
    ]


def build_matrix(
    feature_docs,
    feature_names,
    transform="none"
):

    matrix = []

    for document in feature_docs:

        features = document["data"].get(
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
        dtype=float
    )

    if transform == "log1p":

        matrix = np.log1p(
            matrix
        )

    return matrix


def store_result(
    document,
    score,
    prediction,
    model_version
):

    data = document["data"]

    result = {

        "@timestamp": data["@timestamp"],

        "event": {
            "source": "anomalyspike",
            "type": "anomaly_detection"
        },

        "source": data["source"],

        "features": data["features"],

        "anomaly": {

            "is_anomaly": bool(
                prediction == 1
            ),

            "score": float(
                score
            ),

            "model": "isolation_forest",

            "version": model_version
        },

        "anomalyspike": {

            "sensor": "sensor-01",

            "pipeline": "ml-scoring"
        }
    }

    client.index(
        index=ANOMALIES_INDEX,
        id=document["id"],
        body=result
    )


def save_last_scored_timestamp(
    timestamp
):

    client.index(
        index=STATE_INDEX,
        id=STATE_ID,
        body={
            "last_scored_timestamp": timestamp
        }
    )


def run():

    (
        model,
        feature_names,
        transform,
        model_version
    ) = load_model()

    last_timestamp = (
        get_last_scored_timestamp()
    )

    if last_timestamp:

        print(
            "[SCORER] Last scored timestamp: "
            + last_timestamp
        )

    else:

        print(
            "[SCORER] No previous scoring "
            "state found"
        )

    feature_docs = get_new_features(
        last_timestamp
    )

    if not feature_docs:

        print(
            "[SCORER] No new feature windows "
            "to score"
        )

        return

    print(
        f"[SCORER] New feature windows: "
        f"{len(feature_docs)}"
    )

    matrix = build_matrix(
        feature_docs,
        feature_names,
        transform
    )

    print(
        f"[SCORER] Scoring matrix: "
        f"{matrix.shape}"
    )

    scores = model.decision_function(
        matrix
    )

    predictions = model.predict(
        matrix
    )

    anomalies = 0

    for (
        document,
        score,
        prediction
    ) in zip(
        feature_docs,
        scores,
        predictions
    ):

        store_result(
            document,
            score,
            prediction,
            model_version
        )

        # PyOD convention:
        # 0 = normal
        # 1 = outlier
        if prediction == 1:

            anomalies += 1

    newest_timestamp = (
        feature_docs[-1]["data"]["@timestamp"]
    )

    save_last_scored_timestamp(
        newest_timestamp
    )

    print(
        f"[SCORER] Scored "
        f"{len(feature_docs)} new windows"
    )

    print(
        f"[SCORER] Anomalies: "
        f"{anomalies}"
    )

    print(
        "[SCORER] Scoring state updated"
    )


if __name__ == "__main__":
    run()
