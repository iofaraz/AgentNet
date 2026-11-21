"""AgentNet A2A client.

Run directly to send the benign test messages by hand:
    python client.py

send_messages() is also used by the session runner, so it returns each
agent reply instead of only printing it.
"""

import asyncio

from a2a.client import ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageRequest

AGENT_URL = "http://127.0.0.1:9999"

MESSAGES = [
    "Hello from AgentNet!",
    "What services do you provide?",
    "Can you introduce yourself?",
    "Explain your echo functionality.",
    "This is benign test message five.",
    "Testing normal agent communication.",
    "Please repeat this test message.",
    "AgentNet A2A communication test.",
    "Checking another message response.",
    "Final benign test message.",
]


def _reply_text(chunk) -> str:
    """Text of an agent reply (a StreamResponse carrying a message)."""
    return "".join(part.text for part in chunk.message.parts)


async def send_messages(messages=MESSAGES, agent_url=AGENT_URL, delay=1.0, on_reply=None):
    """Send each message to the agent, one at a time.

    Returns one entry per message: the agent's reply text, or None if the
    request failed or got no reply. on_reply(index, sent, reply_or_error) is
    called after each message, if given.
    """
    client = await create_client(
        agent=agent_url,
        client_config=ClientConfig(streaming=False),
    )
    replies = []
    try:
        for index, text in enumerate(messages, start=1):
            request = SendMessageRequest(message=new_text_message(text, role=Role.ROLE_USER))
            reply = None
            try:
                parts = [_reply_text(chunk) async for chunk in client.send_message(request)]
                reply = "".join(parts) if parts else None
                outcome = reply if reply is not None else "No response received."
            except Exception as error:
                outcome = f"Request failed: {error}"
            replies.append(reply)
            if on_reply:
                on_reply(index, text, outcome)
            if index < len(messages):
                await asyncio.sleep(delay)
    finally:
        await client.close()
    return replies


async def main():
    def show(index, sent, outcome):
        print(f"\n--- Request {index}/{len(MESSAGES)} ---")
        print("Client:", sent)
        print("Agent:", outcome)

    replies = await send_messages(on_reply=show)
    successful = sum(reply is not None for reply in replies)

    print("\n========== SUMMARY ==========")
    print("Successful requests:", successful)
    print("Failed requests:", len(replies) - successful)
    print("Total requests:", len(replies))


if __name__ == "__main__":
    asyncio.run(main())
