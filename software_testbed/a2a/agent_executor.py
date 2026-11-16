
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.helpers import new_text_message


class EchoAgentExecutor(AgentExecutor):
    """A deterministic A2A agent for AgentNet experiments."""

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        text = context.get_user_input()

        response = f"Echo Agent received: {text}"

        await event_queue.enqueue_event(
            new_text_message(response)
        )

    async def cancel(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        raise RuntimeError("Cancellation is not supported.")
