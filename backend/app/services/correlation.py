from collections import defaultdict
from datetime import datetime, timezone

from opensearchpy import OpenSearch


OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
EVENTS_INDEX = "anomalyspike-events"
CORRELATED_INDEX = "anomalyspike-correlated"


client = OpenSearch(
    hosts=[
        {
            "host": OPENSEARCH_HOST,
            "port": OPENSEARCH_PORT
        }
    ]
)


def get_recent_events(size=500):
    response = client.search(
        index=EVENTS_INDEX,
        body={
            "size": size,
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
        hit["_source"]
        for hit in response["hits"]["hits"]
    ]


def correlate_events(events):
    hosts = defaultdict(
        lambda: {
            "dns_queries": [],
            "connections": [],
            "destination_ips": set()
        }
    )

    for event in events:
        source = event.get("source", {})
        source_ip = source.get("ip")

        if not source_ip:
            continue

        event_type = event.get("event", {}).get("type")

        if event_type == "dns":
            query = event.get("zeek", {}).get("query")

            if query:
                hosts[source_ip]["dns_queries"].append(query)

        elif event_type == "connection":
            destination_ip = event.get("destination", {}).get("ip")

            hosts[source_ip]["connections"].append({
                "destination_ip": destination_ip,
                "destination_port": event.get(
                    "destination", {}
                ).get("port"),
                "timestamp": event.get("@timestamp")
            })

            if destination_ip:
                hosts[source_ip]["destination_ips"].add(
                    destination_ip
                )

    results = []

    for source_ip, data in hosts.items():

        result = {
            "@timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "event": {
                "source": "anomalyspike",
                "type": "correlation"
            },

            "source": {
                "ip": source_ip
            },

            "anomalyspike": {
                "sensor": "sensor-01",
                "pipeline": "correlation"
            },

            "behavior": {
                "dns_query_count": len(
                    data["dns_queries"]
                ),

                "connection_count": len(
                    data["connections"]
                ),

                "unique_destination_count": len(
                    data["destination_ips"]
                ),

                "dns_queries": list(
                    set(data["dns_queries"])
                )
            }
        }

        results.append(result)

    return results


def store_correlations(results):
    for result in results:
        client.index(
            index=CORRELATED_INDEX,
            body=result
        )


def run():
    print("[CORRELATION] Reading events...")

    events = get_recent_events()

    print(
        f"[CORRELATION] Retrieved {len(events)} events"
    )

    results = correlate_events(events)

    print(
        f"[CORRELATION] Generated {len(results)} "
        "host profiles"
    )

    store_correlations(results)

    print(
        "[CORRELATION] Correlation completed successfully"
    )


if __name__ == "__main__":
    run()
