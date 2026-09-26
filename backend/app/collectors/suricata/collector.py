import json
import os
import time

from opensearchpy import OpenSearch


SURICATA_EVE_LOG = os.getenv(
    "SURICATA_EVE_LOG",
    "/var/log/suricata/eve.json",
)

OPENSEARCH_HOST = os.getenv(
    "OPENSEARCH_HOST",
    "http://127.0.0.1:9200",
)

INDEX_NAME = "anomalystrike-alerts"

POLL_INTERVAL = 1.0


opensearch = OpenSearch(OPENSEARCH_HOST)


def ensure_index():
    if opensearch.indices.exists(index=INDEX_NAME):
        return

    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {
                    "properties": {
                        "source": {"type": "keyword"},
                        "type": {"type": "keyword"},
                    }
                },
                "source": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "integer"},
                    }
                },
                "destination": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "integer"},
                    }
                },
                "network": {
                    "properties": {
                        "transport": {"type": "keyword"},
                        "protocol": {"type": "keyword"},
                    }
                },
                "suricata": {
                    "properties": {
                        "event_type": {"type": "keyword"},
                        "signature_id": {"type": "integer"},
                        "signature": {"type": "text"},
                        "category": {"type": "keyword"},
                        "severity": {"type": "integer"},
                        "action": {"type": "keyword"},
                        "gid": {"type": "integer"},
                        "rev": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                    }
                },
                "anomalystrike": {
                    "properties": {
                        "sensor": {"type": "keyword"},
                        "pipeline": {"type": "keyword"},
                    }
                },
            }
        }
    }

    opensearch.indices.create(
        index=INDEX_NAME,
        body=mapping,
    )

    print(f"[SURICATA] Created index: {INDEX_NAME}")


def transform_alert(event):
    alert = event.get("alert", {})

    source = event.get("src_ip")
    destination = event.get("dest_ip")

    document = {
        "@timestamp": event.get("timestamp"),

        "event": {
            "source": "suricata",
            "type": "alert",
        },

        "source": {
            "ip": source,
            "port": event.get("src_port"),
        },

        "destination": {
            "ip": destination,
            "port": event.get("dest_port"),
        },

        "network": {
            "transport": event.get("proto"),
            "protocol": event.get("app_proto"),
        },

        "suricata": {
            "event_type": event.get("event_type"),
            "signature_id": alert.get("signature_id"),
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "severity": alert.get("severity"),
            "action": alert.get("action"),
            "gid": alert.get("gid"),
            "rev": alert.get("rev"),
            "protocol": event.get("proto"),
        },

        "anomalystrike": {
            "sensor": "sensor-01",
            "pipeline": "suricata-alert-collector",
        },
    }

    return document


def process_line(line):
    line = line.strip()

    if not line:
        return

    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return

    if event.get("event_type") != "alert":
        return

    document = transform_alert(event)

    doc_id = f"{event.get('flow_id')}-{document['suricata']['signature_id']}-{event.get('timestamp')}"

    response = opensearch.index(
        index=INDEX_NAME,
        id=doc_id,
        body=document,
    )

    print(
        "[SURICATA] Alert indexed:",
        response.get("_id"),
        document["suricata"].get("signature"),
    )


def follow_file(path):
    print(f"[SURICATA] Watching: {path}")

    with open(path, "r") as logfile:
        logfile.seek(0, os.SEEK_END)

        while True:
            line = logfile.readline()

            if line:
                process_line(line)
            else:
                time.sleep(POLL_INTERVAL)


def main():
    print("[SURICATA] Starting collector")
    print(f"[SURICATA] EVE log: {SURICATA_EVE_LOG}")
    print(f"[SURICATA] OpenSearch: {OPENSEARCH_HOST}")

    ensure_index()
    follow_file(SURICATA_EVE_LOG)


if __name__ == "__main__":
    main()
