"""
Example: Running a NANDA-compatible agent registry

This example shows how to use sm-bridge to create a simple
agent registry that's compatible with the NANDA ecosystem.

Run with:
    uvicorn examples.example_registry:app --reload
"""

from fastapi import FastAPI

from sm_bridge import (
    SmBridge,
    SmTool,
    SimpleAgent,
)

# Create the NANDA bridge
bridge = SmBridge(
    registry_id="example-registry",
    provider_name="Example Corp",
    provider_url="https://example.com",
    base_url="http://localhost:8000",
    tools=[
        SmTool(
            tool_id="web-search",
            description="Search the web for information",
            endpoint="http://localhost:8000/tools/search",
            params=["query", "limit"],
        ),
    ],
)

# Register some example agents
bridge.register_agent(
    SimpleAgent(
        id="assistant-v1",
        name="General Assistant",
        description="A helpful AI assistant for general tasks",
        namespace="production",
        version="1.0.0",
        labels=["assistant", "chat", "general"],
        skills=[
            {
                "id": "urn:example:cap:chat:v1",
                "description": "Natural language conversation",
                "inputModes": ["text"],
                "outputModes": ["text"],
            },
            {
                "id": "urn:example:cap:summarize:v1",
                "description": "Summarize long documents",
                "inputModes": ["text"],
                "outputModes": ["text"],
            },
        ],
        endpoints={
            "chat": "http://localhost:8000/agents/assistant-v1/chat",
            "mcp": "http://localhost:8000/agents/assistant-v1/mcp",
        },
        metadata={
            "model": "gpt-4",
            "max_tokens": 4096,
        },
    )
)

bridge.register_agent(
    SimpleAgent(
        id="code-reviewer",
        name="Code Review Agent",
        description="Reviews code for bugs, style issues, and security vulnerabilities",
        namespace="production",
        version="2.1.0",
        labels=["code", "review", "security"],
        skills=[
            {
                "id": "urn:example:cap:code-review:v1",
                "description": "Review code for issues",
                "inputModes": ["text"],
                "outputModes": ["text", "json"],
            },
            {
                "id": "urn:example:cap:security-scan:v1",
                "description": "Scan code for security vulnerabilities",
                "inputModes": ["text"],
                "outputModes": ["json"],
            },
        ],
        endpoints={
            "review": "http://localhost:8000/agents/code-reviewer/review",
        },
        metadata={
            "languages": ["python", "javascript", "typescript", "go", "rust"],
        },
    )
)

bridge.register_agent(
    SimpleAgent(
        id="data-analyst",
        name="Data Analysis Agent",
        description="Analyzes data and generates insights",
        namespace="beta",
        version="0.9.0",
        labels=["data", "analytics", "visualization"],
        skills=[
            {
                "id": "urn:example:cap:analyze:v1",
                "description": "Analyze datasets",
                "inputModes": ["text", "csv"],
                "outputModes": ["text", "json", "chart"],
            },
        ],
    )
)

# Create FastAPI app
app = FastAPI(
    title="Example NANDA Registry",
    description="A NANDA-compatible agent registry built with sm-bridge",
    version="1.0.0",
)

# Mount NANDA routers — main endpoints + well-known discovery at domain root
app.include_router(bridge.router)
app.include_router(bridge.wellknown_router)


# Add a simple health check
@app.get("/health")
def health():
    return {"status": "healthy"}


# Add example tool endpoint
@app.get("/tools/search")
def tool_search(query: str, limit: int = 10):
    """Example MCP tool endpoint."""
    return {
        "query": query,
        "results": [
            {"title": f"Result {i}", "url": f"https://example.com/{i}"}
            for i in range(min(limit, 5))
        ],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
