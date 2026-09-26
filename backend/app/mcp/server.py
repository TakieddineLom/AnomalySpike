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
    name="AnomalyStrike",
    version="0.1.0",
    description="AnomalyStrike network security investigation server"
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
        index="anomalystrike-events",
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
        index="anomalystrike-anomalies",
        body={
            "size": size,
            "query": query,
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )

    return [hit["_source"] for hit in response["hits"]["hits"]]


async def get_host_profile(source_ip: str):
    response = client.search(
        index="anomalystrike-correlated",
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
        index="anomalystrike-events",
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

    # Build a security-focused RAG query from the latest anomaly evidence.
    knowledge_query = (
        "network security anomaly detection "
        "host behavior "
    )

    latest_features = {}

    if anomalies:
        latest = anomalies[0]
        latest_features = latest.get("features", {})

        connection_count = latest_features.get("connection_count", 0)
        unique_destinations = latest_features.get(
            "unique_destination_count", 0
        )
        failed_connections = latest_features.get(
            "failed_connection_count", 0
        )
        dns_queries = latest_features.get("dns_query_count", 0)

        knowledge_query += (
            f"high connection count {connection_count} "
            f"unique destinations {unique_destinations} "
            f"failed connections {failed_connections} "
            f"DNS queries {dns_queries}"
        )

    knowledge = await search_knowledge(
        query=knowledge_query,
        top_k=3,
    )

    # ---------------------------------------------------------
    # Deterministic security interpretation
    # ---------------------------------------------------------

    observations = []
    investigation_focus = []

    connection_count = latest_features.get("connection_count", 0)
    unique_destinations = latest_features.get(
        "unique_destination_count", 0
    )
    failed_connections = latest_features.get(
        "failed_connection_count", 0
    )
    dns_queries = latest_features.get("dns_query_count", 0)

    if anomalies:
        observations.append(
            f"{len(anomalies)} detected anomaly event(s) were identified "
            f"for host {source_ip}."
        )

    if connection_count > 0:
        observations.append(
            f"The latest anomaly window contained "
            f"{connection_count} network connections."
        )

    if unique_destinations > 0:
        observations.append(
            f"The host communicated with "
            f"{unique_destinations} unique destination(s)."
        )

    if failed_connections > 0:
        observations.append(
            f"The anomaly window contained "
            f"{failed_connections} failed connection(s)."
        )

        investigation_focus.append(
            "Review destination IPs, destination ports, connection frequency, "
            "and whether the failed connections are part of repeated attempts."
        )

    if dns_queries > 0:
        observations.append(
            f"The anomaly window contained "
            f"{dns_queries} DNS quer{ 'y' if dns_queries == 1 else 'ies' }."
        )

        investigation_focus.append(
            "Review queried domains and their frequency against the host baseline."
        )

    if connection_count > 0 and unique_destinations > 1:
        investigation_focus.append(
            "Review the destination distribution and determine whether the "
            "connection volume is consistent with expected host activity."
        )

    if not anomalies:
        assessment = (
            "No detected anomalies were found for this host in the "
            "available anomaly index."
        )
    else:
        assessment = (
            "The host exhibits behavior that was flagged by the anomaly "
            "detection pipeline. The observed behavior should be compared "
            "with the host's normal baseline and operational role before "
            "determining whether it represents malicious activity."
        )

    if not investigation_focus:
        investigation_focus.append(
            "Compare the observed behavior with the host's historical baseline "
            "and expected network activity."
        )

    return {
        "source_ip": source_ip,
        "profile": profile,
        "anomalies": anomalies,
        "timeline": timeline,
        "knowledge": knowledge,
        "interpretation": {
            "observations": observations,
            "assessment": assessment,
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
    description="Search the AnomalyStrike security knowledge base using semantic similarity.",
)

server.add_tool(
    search_events,
    name="search_events",
    description="Search normalized AnomalyStrike network events.",
)

server.add_tool(
    get_anomalies,
    name="get_anomalies",
    description="Retrieve detected AnomalyStrike anomalies.",
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
        "[MCP] AnomalyStrike MCP server starting on http://0.0.0.0:8765/mcp ...",
        file=__import__("sys").stderr,
    )

    await server.run_streamable_http_async(
        host="0.0.0.0",
        port=8765,
    )


if __name__ == "__main__":
    asyncio.run(main())
