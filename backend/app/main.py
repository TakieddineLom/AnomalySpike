
import json
from pathlib import Path
import socket
import psutil
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from opensearchpy import OpenSearch
from backend.app.rag.search import search as search_knowledge


MONITORING_INTERFACE = None

MONITORING_CONFIG = Path(
    "/home/taki/AnomalySpike/config/monitoring.json"
)


app = FastAPI(
    title="AnomalySpike API",
    version="0.2.0",
    description="Network security monitoring and anomaly detection platform",
)

opensearch = OpenSearch(
    hosts=[
        {
            "host": "localhost",
            "port": 9200,
        }
    ]
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
def root_redirect():
    return FileResponse("frontend/dashboard.html")

@app.get("/dashboard")
def serve_dashboard():
    return FileResponse("frontend/dashboard.html")
@app.get("/alerts")
def serve_alerts():
    return FileResponse("frontend/alerts.html")

@app.get("/connections")
def serve_connections():
    return FileResponse("frontend/connections.html")

@app.get("/dns")
def serve_dns():
    return FileResponse("frontend/dns.html")

@app.get("/threats")
def serve_threats():
    return FileResponse("frontend/threats.html")

@app.get("/hosts")
def serve_hosts():
    return FileResponse("frontend/hosts.html")

@app.get("/settings")
def serve_settings():
    return FileResponse("frontend/settings.html")


@app.get("/api/status")
def root():
    return {
        "name": "AnomalySpike",
        "version": "0.2.0",
        "status": "online",
    }

@app.get("/api/interfaces/selected")
def get_selected_interface():
    return {
        "interface": MONITORING_INTERFACE
    }

@app.get("/api/knowledge/search")
def knowledge_search(q: str, top_k: int = 3):
    results = search_knowledge(q, top_k=top_k)
    return {"query": q, "results": results}

@app.post("/api/interfaces/select")
def select_interface(interface: str):
    global MONITORING_INTERFACE

    MONITORING_INTERFACE = interface

    with open(MONITORING_CONFIG, "w") as f:
        json.dump(
            {"interface": interface},
            f,
            indent=4
        )

    return {
        "status": "ok",
        "interface": interface
    }


@app.get("/api/interfaces")
def get_interfaces():

    interfaces = []

    for name, addresses in psutil.net_if_addrs().items():

        ipv4 = None

        for address in addresses:
            if address.family == socket.AF_INET:
                ipv4 = address.address
                break

        stats = psutil.net_if_stats().get(name)

        interfaces.append({
            "name": name,
            "ip": ipv4,
            "status": "up" if stats and stats.isup else "down",
            "speed_mbps": stats.speed if stats else 0
        })

    return {
        "count": len(interfaces),
        "interfaces": interfaces
    }

@app.get("/api/health")
def health():
    try:
        info = opensearch.info()

        return {
            "status": "healthy",
            "opensearch": "connected",
            "version": info["version"]["number"],
        }

    except Exception as e:
        return {
            "status": "unhealthy",
            "opensearch": "disconnected",
            "error": str(e),
        }

@app.get("/api/networks")
def get_networks():
    return {
        "count": 1,
        "networks": [
            {
                "id": "lan-01",
                "name": "LAN",
                "interface": "ens33",
                "cidr": "192.168.80.0/24",
                "sensor": "sensor-01"
            }
        ]
    }

@app.get("/api/events")
def get_events(size: int = 100, event_type: str = None):
    query = {"match_all": {}}

    if event_type:
        query = {"term": {"event.type": event_type}}

    response = opensearch.search(
        index="anomalyspike-events",

   body={
            "size": size,
            "query": query,
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
    )

    events = []

    for hit in response["hits"]["hits"]:
        events.append({
            "id": hit["_id"],
            "index": hit["_index"],
            "data": hit["_source"],
        })

    return {
        "count": len(events),
        "events": events,
    }

@app.get("/api/events/timeseries")
def get_events_timeseries(hours: int = 24):
    response = opensearch.search(
        index="anomalyspike-events",
        body={
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{hours}h",
                        "lte": "now"
                    }
                }
            },
            "aggs": {
                "events_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0
                    }
                }
            }
        }
    )

    buckets = response["aggregations"]["events_over_time"]["buckets"]

    return {
        "hours": hours,
        "points": [
            {
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            }
            for bucket in buckets
        ]
    }


@app.get("/api/anomalies")
def get_anomalies(size: int = 100):
    response = opensearch.search(
        index="anomalyspike-anomalies",
        body={
            "size": size,
            "query": {
                "term": {
                    "anomaly.is_anomaly": True
                }
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

    anomalies = []

    for hit in response["hits"]["hits"]:
        anomalies.append({
            "id": hit["_id"],
            "data": hit["_source"],
        })

    return {
        "count": len(anomalies),
        "anomalies": anomalies,
    }


@app.get("/api/hosts")
def get_hosts(size: int = 100):
    response = opensearch.search(
        index="anomalyspike-correlated",
        body={
            "size": size,
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

    hosts = []

    for hit in response["hits"]["hits"]:
        hosts.append({
            "id": hit["_id"],
            "data": hit["_source"],
        })

    return {
        "count": len(hosts),
        "hosts": hosts,
    }


@app.get("/api/hosts/live")
def get_live_hosts(hours: int = 24):
    response = opensearch.search(
        index="anomalyspike-events",
        body={
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{hours}h"
                    }
                }
            },
            "aggs": {
                "hosts": {
                    "terms": {
                        "field": "source.ip",
                        "size": 100
                    },
                    "aggs": {
                        "last_seen": {
                            "max": {
                                "field": "@timestamp"
                            }
                        },
                        "first_seen": {
                            "min": {
                                "field": "@timestamp"
                            }
                        },
                        "unique_destinations": {
                            "cardinality": {
                                "field": "destination.ip"
                            }
                        }
                    }
                }
            }
        }
    )

    buckets = response["aggregations"]["hosts"]["buckets"]

    hosts = []
    for bucket in buckets:
        hosts.append({
            "ip": bucket["key"],
            "connection_count": bucket["doc_count"],
            "unique_destinations": bucket["unique_destinations"]["value"],
            "first_seen": bucket["first_seen"]["value_as_string"],
            "last_seen": bucket["last_seen"]["value_as_string"],
        })

    return {
        "count": len(hosts),
        "hosts": hosts,
    }

@app.get("/api/hosts/{ip}/timeline")
def get_host_timeline(ip: str, size: int = 100):
    response = opensearch.search(
        index="anomalyspike-events",
        body={
            "size": size,
            "query": {
                "term": {
                    "source.ip": ip
                }
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

    events = []

    for hit in response["hits"]["hits"]:
        events.append({
            "id": hit["_id"],
            "index": hit["_index"],
            "data": hit["_source"],
        })

    return {
        "host": ip,
        "count": len(events),
        "events": events,
    }


@app.get("/api/stats")
def get_stats():
    events_count = opensearch.count(
        index="anomalyspike-events"
    )["count"]

    anomalies_count = opensearch.count(
    index="anomalyspike-anomalies",
    body={
        "query": {
            "term": {
                "anomaly.is_anomaly": True
            }
        }
    }
)["count"]

    hosts_response = opensearch.search(
        index="anomalyspike-events",
        body={
            "size": 0,
            "aggs": {
                "unique_hosts": {
                    "cardinality": {
                        "field": "source.ip"
                    }
                }
            }
        }
    )

    hosts_count = (
        hosts_response["aggregations"]["unique_hosts"]["value"]
    )

    return {
        "events": events_count,
        "anomalies": anomalies_count,
        "hosts": hosts_count,
    }
@app.get("/api/alerts")
def get_alerts(size: int = 100):
    response = opensearch.search(
        index="anomalyspike-alerts",
        body={
            "size": size,
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

    alerts = []

    for hit in response["hits"]["hits"]:
        alerts.append({
            "id": hit["_id"],
            "data": hit["_source"],
        })

    return {
        "count": len(alerts),
        "alerts": alerts,
    }
