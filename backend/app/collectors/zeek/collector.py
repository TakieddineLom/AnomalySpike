import json
import os
import time
from datetime import datetime, timezone

from opensearchpy import OpenSearch


ZEEK_LOG = os.getenv(
    "ZEEK_CONN_LOG",
    "/home/taki/AnomalyStrike/conn.log"
)

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_INDEX = os.getenv(
    "OPENSEARCH_INDEX",
    "anomalystrike-events"
)


client = OpenSearch(
    hosts=[
        {
            "host": OPENSEARCH_HOST,
            "port": OPENSEARCH_PORT
        }
    ]
)


def normalize_event(event):
    timestamp = datetime.fromtimestamp(
        event["ts"],
        tz=timezone.utc
    ).isoformat()

    return {
        "@timestamp": timestamp,

        "event": {
            "source": "zeek",
            "type": "connection"
        },

        "source": {
            "ip": event.get("id.orig_h"),
            "port": event.get("id.orig_p")
        },

        "destination": {
            "ip": event.get("id.resp_h"),
            "port": event.get("id.resp_p")
        },

        "network": {
            "transport": event.get("proto"),
            "protocol": event.get("ip_proto")
        },

        "zeek": {
            "uid": event.get("uid"),
            "service": event.get("service"),
            "duration": event.get("duration"),
            "orig_bytes": event.get("orig_bytes"),
            "resp_bytes": event.get("resp_bytes"),
            "conn_state": event.get("conn_state"),
            "history": event.get("history"),
            "orig_pkts": event.get("orig_pkts"),
            "resp_pkts": event.get("resp_pkts"),
            "orig_ip_bytes": event.get("orig_ip_bytes"),
            "resp_ip_bytes": event.get("resp_ip_bytes"),
            "missed_bytes": event.get("missed_bytes")
        },

        "anomalystrike": {
            "sensor": "sensor-01",
            "pipeline": "zeek"
        }
    }


def send_to_opensearch(event):
    response = client.index(
        index=OPENSEARCH_INDEX,
        body=event
    )

    return response


def process_line(line):
    line = line.strip()

    if not line:
        return

    try:
        event = json.loads(line)

        normalized = normalize_event(event)

        response = send_to_opensearch(normalized)

        print(
            f"[ZEek] Indexed event "
            f"id={response['_id']} "
            f"source={normalized['source']['ip']} "
            f"destination={normalized['destination']['ip']}"
        )

    except json.JSONDecodeError:
        print("[ZEEK] Skipping invalid JSON line")

    except Exception as error:
        print(f"[ZEEK] Collector error: {error}")


def collect():
    print(f"[ZEEK] Monitoring: {ZEEK_LOG}")

    with open(ZEEK_LOG, "r") as logfile:

        # Start at the end of the file.
        logfile.seek(0, os.SEEK_END)

        while True:

            line = logfile.readline()

            if not line:
                time.sleep(0.5)
                continue

            process_line(line)


if __name__ == "__main__":
    collect()
