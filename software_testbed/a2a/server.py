
import uvicorn

from starlette.applications import Starlette

from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.server.tasks import InMemoryTaskStore

from a2a.types import (
    AgentCard,
    AgentCapabilities,
    AgentInterface,
    AgentSkill,
)

from agent_executor import EchoAgentExecutor


# Define agent skill
skill = AgentSkill(
    id="echo",
    name="Echo",
    description="Returns the received text.",
    tags=["echo", "testing"],
    examples=["Hello Agent"],
)


# Define agent card
agent_card = AgentCard(
    name="AgentNet Echo Agent",
    description="A deterministic echo agent for AgentNet experiments.",
    version="1.0.0",
    default_input_modes=["text"],
    default_output_modes=["text"],
    capabilities=AgentCapabilities(
        streaming=False,
    ),
    supported_interfaces=[
        AgentInterface(
            protocol_binding="JSONRPC",
            url="http://127.0.0.1:9999/",
            protocol_version="1.0",
        )
    ],
    skills=[skill],
)


# Configure request handler
request_handler = DefaultRequestHandler(
    agent_executor=EchoAgentExecutor(),
    task_store=InMemoryTaskStore(),
    agent_card=agent_card,
)


# Configure A2A routes
routes = []

routes.extend(create_agent_card_routes(agent_card))
routes.extend(create_jsonrpc_routes(request_handler, "/"))


# Create application
app = Starlette(routes=routes)


if __name__ == "__main__":
    print("Starting AgentNet A2A Echo Agent...")
    print("Endpoint: http://127.0.0.1:9999/")
    print("Agent Card: http://127.0.0.1:9999/.well-known/agent-card.json")

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=9999,
    )
