import hashlib
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from opensearchpy import OpenSearch


ZEEK_LOG = os.getenv(
    "ZEEK_HTTP_LOG",
    "/home/taki/AnomalySpike/http.log",
)

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_INDEX = os.getenv(
    "OPENSEARCH_INDEX",
    "anomalyspike-events",
)

client = OpenSearch(
    hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}]
)


def normalize_uri(value):
    """Remove query strings and fragments to avoid indexing tokens."""
    if not value:
        return None

    parsed = urlsplit(value)
    return parsed.path or "/"


def normalize_event(event):
    timestamp = datetime.fromtimestamp(
        event["ts"], tz=timezone.utc
    ).isoformat()

    uid = event.get("uid", "")
    depth = event.get("trans_depth", 0)
    source_ip = event.get("id.orig_h")
    source_port = event.get("id.orig_p")
    destination_ip = event.get("id.resp_h")
    destination_port = event.get("id.resp_p")

    identity = (
        f"{uid}|{depth}|{event['ts']}|"
        f"{event.get('method', '')}|{event.get('uri', '')}"
    )
    document_id = hashlib.sha256(identity.encode()).hexdigest()

    normalized = {
        "@timestamp": timestamp,
        "event": {
            "source": "zeek",
            "type": "http",
        },
        "source": {
            "ip": source_ip,
            "port": source_port,
        },
        "destination": {
            "ip": destination_ip,
            "port": destination_port,
        },
        "network": {
            "transport": "tcp",
            "protocol": 6,
        },
        "zeek": {
            "uid": uid or None,
            "http": {
                "trans_depth": depth,
                "method": event.get("method"),
                "host": event.get("host"),
                "uri": normalize_uri(event.get("uri")),
                "version": event.get("version"),
                "user_agent": event.get("user_agent"),
                "referrer": event.get("referrer"),
                "request_body_len": event.get("request_body_len"),
                "response_body_len": event.get("response_body_len"),
                "status_code": event.get("status_code"),
                "status_msg": event.get("status_msg"),
                "request_mime_types": event.get("orig_mime_types"),
                "response_mime_types": event.get("resp_mime_types"),
                "tags": event.get("tags"),
            },
        },
        "anomalyspike": {
            "sensor": "sensor-01",
            "pipeline": "zeek-http",
        },
    }

    return document_id, normalized


def process_line(line):
    line = line.strip()
    if not line:
        return

    try:
        event = json.loads(line)
        document_id, normalized = normalize_event(event)

        client.index(
            index=OPENSEARCH_INDEX,
            id=document_id,
            body=normalized,
        )

    except json.JSONDecodeError:
        print("[ZEEK-HTTP] Skipping invalid JSON line")
    except Exception as error:
        print(f"[ZEEK-HTTP] Collector error: {error}")


def collect():
    print(f"[ZEEK-HTTP] Monitoring: {ZEEK_LOG}")

    while not os.path.isfile(ZEEK_LOG):
        print(f"[ZEEK-HTTP] Waiting for log file: {ZEEK_LOG}")
        time.sleep(2)

    with open(ZEEK_LOG, "r", encoding="utf-8") as logfile:
        logfile.seek(0, os.SEEK_END)

        while True:
            line = logfile.readline()
            if not line:
                time.sleep(0.5)
                continue

            process_line(line)


if __name__ == "__main__":
    collect()
