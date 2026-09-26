import asyncio
import json

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


SERVER_URL = "http://192.168.80.130:8765/mcp"


async def main():
    async with streamable_http_client(SERVER_URL) as (read, write):
        async with ClientSession(read, write) as session:

            await session.initialize()

            print("=== Available tools ===")
            tools = await session.list_tools()
            for tool in tools.tools:
                print(f"- {tool.name}: {tool.description}")

            print("\n=== Calling search_knowledge ===")
            result = await session.call_tool(
                "search_knowledge",
                {"query": "lateral movement", "top_k": 2}
            )
            for content in result.content:
                print(content.text[:500])

            print("\n=== Calling get_anomalies ===")
            result = await session.call_tool(
                "get_anomalies",
                {"size": 3}
            )
            for content in result.content:
                print(content.text[:1000])

            print("\n=== Calling investigate_host ===")
            result = await session.call_tool(
                "investigate_host",
                {"source_ip": "192.168.80.130"}
            )
            for content in result.content:
                print(content.text[:1500])


if __name__ == "__main__":
    asyncio.run(main())
