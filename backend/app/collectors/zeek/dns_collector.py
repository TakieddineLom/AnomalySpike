import json
import os
import time
from datetime import datetime, timezone

from opensearchpy import OpenSearch


ZEEK_LOG = os.getenv(
    "ZEEK_DNS_LOG",
    "/home/taki/AnomalyStrike/data/zeek/json-test/dns.log"
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
            "type": "dns"
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
            "transport": "udp",
            "protocol": 17
        },

        "zeek": {
            "uid": event.get("uid"),
            "query": event.get("query"),
            "qtype_name": event.get("qtype_name"),
            "qtype": event.get("qtype"),
            "rcode_name": event.get("rcode_name"),
            "answers": event.get("answers"),
            "rejected": event.get("rejected")
        },

        "anomalystrike": {
            "sensor": "sensor-01",
            "pipeline": "zeek-dns"
        }
    }


def send_to_opensearch(event):
    return client.index(
        index=OPENSEARCH_INDEX,
        body=event
    )


def process_line(line):
    line = line.strip()

    if not line:
        return

    try:
        event = json.loads(line)
        normalized = normalize_event(event)
        response = send_to_opensearch(normalized)

        print(
            f"[ZEEK-DNS] Indexed event "
            f"id={response['_id']} "
            f"source={normalized['source']['ip']} "
            f"query={normalized['zeek']['query']}"
        )

    except json.JSONDecodeError:
        print("[ZEEK-DNS] Skipping invalid JSON line")

    except Exception as error:
        print(f"[ZEEK-DNS] Collector error: {error}")


def collect():
    print(f"[ZEEK-DNS] Monitoring: {ZEEK_LOG}")

    with open(ZEEK_LOG, "r") as logfile:
        logfile.seek(0, os.SEEK_END)

        while True:
            line = logfile.readline()

            if not line:
                time.sleep(0.5)
                continue

            process_line(line)


if __name__ == "__main__":
    collect()
