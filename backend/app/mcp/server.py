import asyncio
import os
import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer
from mcp.server.mcpserver import MCPServer
from mcp.types import Tool, TextContent
from opensearchpy import OpenSearch


OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

client = OpenSearch(
    hosts=[
        {
            "host": OPENSEARCH_HOST,
            "port": OPENSEARCH_PORT
        }
    ]
)


server = MCPServer(
    name="AnomalySpike",
    version="0.1.0",
    description="AnomalySpike network security investigation server"
)


RAG_INDEX_PATH = (
    Path(__file__).resolve().parents[1]
    / "rag"
    / "rag_index.json"
)

RAG_MODEL_NAME = "all-MiniLM-L6-v2"

rag_model = SentenceTransformer(RAG_MODEL_NAME)


def load_rag_index():
    with open(RAG_INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


async def search_events(
    source_ip: str = None,
    event_type: str = None,
    size: int = 20,
):
    size = min(size, 100)

    filters = []

    if source_ip:
        filters.append({"term": {"source.ip": source_ip}})

    if event_type:
        filters.append({"term": {"event.type": event_type}})

    query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

    response = client.search(
        index="anomalyspike-events",
        body={
            "size": size,
            "query": query,
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )

    return [hit["_source"] for hit in response["hits"]["hits"]]


async def get_anomalies(
    source_ip: str = None,
    size: int = 20,
):
    size = min(size, 100)

    filters = [{"term": {"anomaly.is_anomaly": True}}]

    if source_ip:
        filters.append({"term": {"source.ip": source_ip}})

    query = {"bool": {"filter": filters}}

    response = client.search(
        index="anomalyspike-anomalies",
        body={
            "size": size,
            "query": query,
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )

    return [hit["_source"] for hit in response["hits"]["hits"]]


async def get_host_profile(source_ip: str):
    response = client.search(
        index="anomalyspike-correlated",
        body={
            "size": 1,
            "query": {"term": {"source.ip": source_ip}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )

    if not response["hits"]["hits"]:
        return {"found": False, "source_ip": source_ip}

    return {
        "found": True,
        "profile": response["hits"]["hits"][0]["_source"],
    }


async def get_host_timeline(
    source_ip: str,
    size: int = 50,
):
    size = min(size, 100)

    response = client.search(
        index="anomalyspike-events",
        body={
            "size": size,
            "query": {"term": {"source.ip": source_ip}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )

    return [hit["_source"] for hit in response["hits"]["hits"]]


async def investigate_host(source_ip: str):
    profile = await get_host_profile(source_ip=source_ip)
    anomalies = await get_anomalies(source_ip=source_ip, size=20)
    timeline = await get_host_timeline(source_ip=source_ip, size=50)

    # Summarize HTTP context from the existing host timeline.
    # Informational only: this does not affect anomaly scoring.
    from collections import Counter
    from urllib.parse import urlsplit

    http_events = [
        event for event in timeline
        if event.get("event", {}).get("type") == "http"
    ]

    http_methods = Counter()
    http_status_codes = Counter()
    http_paths = Counter()
    http_destinations = set()

    for event in http_events:
        http = event.get("zeek", {}).get("http", {})

        method = http.get("method")
        if method:
            http_methods[str(method)] += 1

        status = http.get("status_code")
        if status is not None:
            http_status_codes[str(status)] += 1

        uri = http.get("uri")
        if uri:
            # Keep only the path, never query parameters.
            path = urlsplit(str(uri)).path or "/"
            http_paths[path] += 1

        destination = event.get("destination", {})
        ip = destination.get("ip")
        port = destination.get("port")
        if ip:
            http_destinations.add(f"{ip}:{port}" if port else str(ip))

    http_summary = {
        "request_count": len(http_events),
        "methods": dict(http_methods),
        "status_codes": dict(http_status_codes),
        "paths": dict(http_paths.most_common(20)),
        "destinations": sorted(http_destinations),
        "informational_only": True,
    }


    # Retrieve the newest detection window, whether normal or anomalous.
    latest_response = client.search(
        index="anomalyspike-anomalies",
        body={
            "size": 1,
            "query": {"term": {"source.ip": source_ip}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )
    latest_hits = latest_response["hits"]["hits"]
    latest_window = latest_hits[0]["_source"] if latest_hits else {}

    # ---------------------------------------------------------
    # Extract latest detection-window features
    # ---------------------------------------------------------

    latest_features = latest_window.get("features", {})

    connection_count = latest_features.get("connection_count", 0)
    unique_destinations = latest_features.get(
        "unique_destination_count", 0
    )
    failed_connections = latest_features.get(
        "failed_connection_count", 0
    )
    dns_queries = latest_features.get("dns_query_count", 0)

    # ---------------------------------------------------------
    # Build RAG query
    # ---------------------------------------------------------

    knowledge_query = (
        "network security anomaly detection "
        "host behavior "
        f"connection count {connection_count} "
        f"unique destinations {unique_destinations} "
        f"failed connections {failed_connections} "
        f"DNS queries {dns_queries}"
    )

    knowledge = await search_knowledge(
        query=knowledge_query,
        top_k=3,
    )

    # ---------------------------------------------------------
    # Analyze timeline context
    # ---------------------------------------------------------

    timeline_event_types = {}
    timeline_destinations = set()
    timeline_failed = 0

    for event in timeline:
        event_type = event.get("event", {}).get("type")

        if event_type:
            timeline_event_types[event_type] = (
                timeline_event_types.get(event_type, 0) + 1
            )

        destination_ip = event.get("destination", {}).get("ip")

        if destination_ip:
            timeline_destinations.add(destination_ip)

        state = event.get("zeek", {}).get("conn_state") or event.get("zeek", {}).get("conn", {}).get("state")

        if state in {"REJ", "RSTO", "RSTR", "S0"}:
            timeline_failed += 1

    # ---------------------------------------------------------
    # Analyze host profile context
    # ---------------------------------------------------------

    profile_data = profile.get("profile", {}) if profile.get("found") else {}

    profile_features = (profile_data.get("behavior") or profile_data.get("features", {}))

    baseline_context = {
        "profile_available": bool(profile.get("found")),
        "timeline_events": len(timeline),
        "timeline_unique_destinations": len(timeline_destinations),
        "timeline_failed_connections": timeline_failed,
        "timeline_event_types": timeline_event_types,
        "profile_features": profile_features,
        "timeline_limit": 50,
        "http_summary_scope": (
            "HTTP events among the retrieved timeline events only; "
            "not a complete HTTP history."
        ),
    }

    # ---------------------------------------------------------
    # Build observations
    # ---------------------------------------------------------

    observations = []

    if anomalies:
        observations.append(
            f"{len(anomalies)} detected anomaly event(s) were identified "
            f"for host {source_ip}."
        )
    else:
        observations.append(
            f"No detected anomaly events were found for host {source_ip}."
        )

    if connection_count:
        observations.append(
            f"The latest anomaly window contained "
            f"{connection_count} network connections."
        )

    if unique_destinations:
        observations.append(
            f"The latest anomaly window involved "
            f"{unique_destinations} unique destination(s)."
        )

    if failed_connections:
        observations.append(
            f"The latest anomaly window contained "
            f"{failed_connections} failed connection(s)."
        )

    if dns_queries:
        observations.append(
            f"The latest anomaly window contained "
            f"{dns_queries} DNS quer{'y' if dns_queries == 1 else 'ies'}."
        )

    if timeline:
        observations.append(
            f"The available host timeline contains "
            f"{len(timeline)} recent network event(s)."
        )

    if timeline_destinations:
        observations.append(
            f"The recent timeline contains "
            f"{len(timeline_destinations)} unique destination IP(s)."
        )

    if http_events:
        observations.append(
            f"The retrieved timeline includes {len(http_events)} HTTP "
            f"request event(s). Methods: {dict(http_methods)}; "
            f"status codes: {dict(http_status_codes)}."
        )
        if http_paths:
            observations.append(
                f"Observed HTTP paths in the retrieved sample: "
                f"{dict(http_paths.most_common(10))}."
            )
    else:
        observations.append(
            "No HTTP events were present in the retrieved timeline. "
            "This does not establish that the host had no HTTP activity."
        )

    # ---------------------------------------------------------
    # Compare latest anomaly with available timeline context
    # ---------------------------------------------------------

    comparison = {
        "latest_connection_count": connection_count,
        "latest_unique_destinations": unique_destinations,
        "latest_failed_connections": failed_connections,
        "timeline_event_count": len(timeline),
        "timeline_unique_destinations": len(timeline_destinations),
        "timeline_failed_connections": timeline_failed,
    }

    if timeline and unique_destinations:
        if len(timeline_destinations) >= unique_destinations:
            baseline_statement = (
                "The recent timeline contains a destination set at least "
                "as broad as the latest anomalous window. This does not by "
                "itself establish that the latest behavior is malicious."
            )
        else:
            baseline_statement = (
                "The latest anomalous window involves more unique destinations "
                "than are represented in the available recent timeline. "
                "Additional historical data would help determine whether this "
                "is unusual for the host."
            )
    else:
        baseline_statement = (
            "There is insufficient timeline data to establish a reliable "
            "host-specific behavioral baseline."
        )

        # ---------------------------------------------------------
    # Evidence-linked possible explanations
    # ---------------------------------------------------------

    possible_explanations = []

    for item in knowledge:
        source = item.get("source")
        content = item.get("content", "")

        if "Failed Connections" in content and failed_connections:
            possible_explanations.append({
                "behavior": "Failed connections",
                "observed": failed_connections,
                "context": [
                    "Unavailable services",
                    "Network problems",
                    "Repeated connection attempts",
                    "Port scanning",
                ],
                "source": source,
            })

        if "High Connection Volume" in content and connection_count:
            possible_explanations.append({
                "behavior": "High connection volume",
                "observed": connection_count,
                "context": [
                    "Service discovery",
                    "Automated applications",
                    "Monitoring activity",
                    "Misconfiguration",
                    "Network scanning",
                ],
                "source": source,
            })

        if "Repeated Connections" in content:
            possible_explanations.append({
                "behavior": "Repeated connections",
                "observed": None,
                "context": [
                    "Normal application traffic",
                    "Periodic service communication",
                    "Automated processes",
                    "Persistent or repeated suspicious activity",
                ],
                "source": source,
            })

    # ---------------------------------------------------------
    # Investigation focus
    # ---------------------------------------------------------

    investigation_focus = []

    if failed_connections:
        investigation_focus.append(
            "Review destination IPs, destination ports, connection frequency, "
            "and whether failed connections form repeated attempts."
        )

    if unique_destinations:
        investigation_focus.append(
            "Compare the destination distribution of the latest anomaly with "
            "the host's historical communication pattern."
        )

    if connection_count:
        investigation_focus.append(
            "Determine whether the connection volume is expected for the "
            "host's operational role."
        )

    if dns_queries:
        investigation_focus.append(
            "Review queried domains and compare their frequency with the "
            "host's normal DNS behavior."
        )

    if http_events:
        investigation_focus.append(
            "Review HTTP paths, response codes, and destination services "
            "against the host's expected application activity. Treat "
            "successful responses as context, not proof of benign activity."
        )

    if not profile.get("found"):
        investigation_focus.append(
            "Obtain a current correlated host profile before making a "
            "host-specific baseline assessment."
        )

    if not timeline:
        investigation_focus.append(
            "Collect additional timeline data to establish historical behavior."
        )

    if not investigation_focus:
        investigation_focus.append(
            "Compare the observed behavior with the host's historical "
            "baseline and expected operational activity."
        )

    # ---------------------------------------------------------
    # Assessment
    # ---------------------------------------------------------

    latest_anomaly = (latest_window.get("anomaly") or {})
    latest_detection = (latest_window.get("detection") or {})
    latest_timestamp = latest_window.get("@timestamp")

    if not latest_window:
        latest_status = "No detection window is available."
    elif latest_anomaly.get("is_anomaly") is True:
        latest_status = (
            f"The latest detection window at {latest_timestamp} "
            "is flagged as anomalous."
        )
    else:
        latest_status = (
            f"The latest detection window at {latest_timestamp} "
            "is not flagged as anomalous."
        )

    ml_flags = sum(
        1 for item in anomalies
        if (item.get("detection") or {}).get("ml_anomaly")
        or (item.get("anomaly") or {}).get("ml_anomaly")
    )
    behavioral_flags = sum(
        1 for item in anomalies
        if (item.get("detection") or {}).get("behavioral_anomaly")
        or (item.get("anomaly") or {}).get("behavioral_anomaly")
    )

    assessment = (
        f"{latest_status} "
        f"{len(anomalies)} historical flagged record(s) were retrieved "
        f"(query limit: 20); {ml_flags} contain an ML anomaly flag and "
        f"{behavioral_flags} contain a behavioral anomaly flag. "
        "These are detection signals, not confirmed security incidents. "
        "Review underlying events and operational context before drawing "
        "conclusions about malicious activity."
    )


    return {
        "source_ip": source_ip,
        "profile": profile,
        "anomalies": anomalies,
        "latest_window": latest_window or None,
        "timeline": timeline,
        "knowledge": knowledge,
        "http_summary": http_summary,
        "interpretation": {
            "observations": observations,
            "assessment": assessment,
            "baseline_context": baseline_context,
            "comparison": comparison,
            "possible_explanations": possible_explanations,
            "investigation_focus": investigation_focus,
        },
    }


async def search_knowledge(
    query: str,
    top_k: int = 3,
):
    top_k = min(top_k, 10)

    chunks = load_rag_index()

    query_embedding = rag_model.encode(
        query,
        normalize_embeddings=True,
    )

    results = []

    for chunk in chunks:
        embedding = np.array(chunk["embedding"])
        score = float(np.dot(query_embedding, embedding))

        results.append({
            "source": chunk["source"],
            "score": round(score, 4),
            "content": chunk["content"],
        })

    results.sort(key=lambda r: r["score"], reverse=True)

    return results[:top_k]


server.add_tool(
    search_knowledge,
    name="search_knowledge",
    description="Search the AnomalySpike security knowledge base using semantic similarity.",
)

server.add_tool(
    search_events,
    name="search_events",
    description="Search normalized AnomalySpike network events.",
)

server.add_tool(
    get_anomalies,
    name="get_anomalies",
    description="Retrieve detected AnomalySpike anomalies.",
)

server.add_tool(
    get_host_profile,
    name="get_host_profile",
    description="Retrieve the correlated behavioral profile of a host.",
)

server.add_tool(
    get_host_timeline,
    name="get_host_timeline",
    description="Retrieve recent network events for a host.",
)

server.add_tool(
    investigate_host,
    name="investigate_host",
    description="Build a consolidated security investigation for a host using its profile, anomalies, timeline, and recent events.",
)


async def main():
    print(
        "[MCP] AnomalySpike MCP server starting on http://0.0.0.0:8765/mcp ...",
        file=__import__("sys").stderr,
    )

    await server.run_streamable_http_async(
        host="0.0.0.0",
        port=8765,
    )


if __name__ == "__main__":
    asyncio.run(main())
