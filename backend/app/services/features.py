import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from opensearchpy import OpenSearch


OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

EVENTS_INDEX = "anomalystrike-events"
FEATURES_INDEX = "anomalystrike-features"
STATE_INDEX = "anomalystrike-state"
STATE_ID = "feature-extraction"

VERSION = "0.4.0"


client = OpenSearch(
    hosts=[
        {
            "host": OPENSEARCH_HOST,
            "port": OPENSEARCH_PORT
        }
    ]
)


def get_state():
    try:
        response = client.get(
            index=STATE_INDEX,
            id=STATE_ID
        )
        return response["_source"]
    except Exception:
        return {
            "version": VERSION,
            "last_finalized_minute": None
        }


def save_state(last_finalized_minute):
    state = {
        "version": VERSION,
        "last_finalized_minute": last_finalized_minute
    }

    client.index(
        index=STATE_INDEX,
        id=STATE_ID,
        body=state
    )


def get_minute(timestamp):
    dt = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )
    return dt.replace(second=0, microsecond=0)


def get_current_minute():
    now = datetime.now(timezone.utc)
    return now.replace(second=0, microsecond=0)


def get_events_between(start_minute, end_minute):
    filters = [
        {
            "range": {
                "@timestamp": {
                    "gte": start_minute.isoformat(),
                    "lt": end_minute.isoformat()
                }
            }
        }
    ]

    response = client.search(
        index=EVENTS_INDEX,
        body={
            "size": 10000,
            "query": {
                "bool": {
                    "filter": filters
                }
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
        hit["_source"]
        for hit in response["hits"]["hits"]
    ]


def build_feature_window(events, source_ip, minute):
    dns_queries = set()
    connections = 0
    destination_ips = set()
    bytes_sent = 0
    bytes_received = 0
    failed_connections = 0

    for event in events:
        event_source = event.get("source", {}).get("ip")

        if event_source != source_ip:
            continue

        event_type = event.get("event", {}).get("type")

        if event_type == "dns":
            query = event.get("zeek", {}).get("query")

            if query:
                dns_queries.add(query)

        elif event_type == "connection":
            connections += 1

            destination_ip = event.get(
                "destination", {}
            ).get("ip")

            if destination_ip:
                destination_ips.add(destination_ip)

            zeek = event.get("zeek", {})

            bytes_sent += zeek.get("orig_bytes") or 0
            bytes_received += zeek.get("resp_bytes") or 0

            conn_state = zeek.get("conn_state")

            if conn_state in {
                "REJ",
                "RSTO",
                "RSTR",
                "S0"
            }:
                failed_connections += 1

    return {
        "@timestamp": minute.isoformat(),
        "event": {
            "source": "anomalystrike",
            "type": "behavior_features"
        },
        "source": {
            "ip": source_ip
        },
        "features": {
            "dns_query_count": len(dns_queries),
            "connection_count": connections,
            "unique_destination_count": len(destination_ips),
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "failed_connection_count": failed_connections
        },
        "anomalystrike": {
            "sensor": "sensor-01",
            "pipeline": "feature-extraction",
            "version": VERSION
        }
    }


def store_feature(result):
    source_ip = result["source"]["ip"]
    timestamp = result["@timestamp"]

    document_id = f"{source_ip}-{timestamp}"

    client.index(
        index=FEATURES_INDEX,
        id=document_id,
        body=result
    )

    print(
        f"[FEATURES] Stored window "
        f"host={source_ip} time={timestamp}"
    )


def run():
    print("[FEATURES] Starting finalized-minute extraction...")

    state = get_state()

    previous = state.get("last_finalized_minute")

    current_minute = get_current_minute()

    print(
        f"[FEATURES] Current minute: "
        f"{current_minute.isoformat()}"
    )

    if previous:
        start_minute = datetime.fromisoformat(
            previous.replace("Z", "+00:00")
        )
    else:
        start_minute = None

    if start_minute is None:
        print(
            "[FEATURES] No finalized-minute cursor found."
        )

        print(
            "[FEATURES] Initializing cursor to the "
            "current minute without processing it."
        )

        save_state(current_minute.isoformat())

        print(
            "[FEATURES] Initialization completed."
        )

        return

    if start_minute >= current_minute:
        print(
            "[FEATURES] No newly finalized minutes."
        )
        return

    events = get_events_between(
        start_minute,
        current_minute
    )

    print(
        f"[FEATURES] Retrieved {len(events)} events "
        f"from {start_minute.isoformat()} "
        f"to {current_minute.isoformat()}"
    )

    windows = defaultdict(list)

    for event in events:
        timestamp = event.get("@timestamp")
        source_ip = event.get("source", {}).get("ip")

        if not timestamp or not source_ip:
            continue

        minute = get_minute(timestamp)

        if minute >= current_minute:
            continue

        windows[(source_ip, minute)].append(event)

    print(
        f"[FEATURES] Affected host-minute windows: "
        f"{len(windows)}"
    )

    for (source_ip, minute), minute_events in sorted(
        windows.items(),
        key=lambda item: (
            item[0][1],
            item[0][0]
        )
    ):
        result = build_feature_window(
            minute_events,
            source_ip,
            minute
        )

        store_feature(result)

    save_state(current_minute.isoformat())

    print(
        f"[FEATURES] Finalized-minute cursor advanced to: "
        f"{current_minute.isoformat()}"
    )

    print(
        "[FEATURES] Finalized-minute extraction completed."
    )


if __name__ == "__main__":
    run()
