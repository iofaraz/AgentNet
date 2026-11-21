"""AgentNet A2A client: sends requests to the Lab Assistant.

Run directly to send the default requests by hand (MCP and A2A servers running):
    python client.py
    python client.py --principal bob

send_messages() is also used by the session runner, so it returns each
agent reply instead of only printing it. The client authenticates with
"Authorization: Bearer <token>", as the Agent Card requires.
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

import httpx
from a2a.client import ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageRequest

sys.path.append(str(Path(__file__).resolve().parent.parent / "mcp"))
from workspace import DEFAULT_SEED, World  # noqa: E402

AGENT_URL = "http://127.0.0.1:9999"
HTTP_TIMEOUT = 300.0   # the assistant runs a model and MCP calls per request

MESSAGES = [
    "What is the temperature in the lab right now?",
    "Which documents are in the docs folder?",
    "What is the weather in Islamabad?",
]


def token_for(principal: str) -> str:
    seed = int(os.environ.get("AGENTNET_SEED", DEFAULT_SEED))
    return World(seed).token_for(principal)


def _reply_text(chunk) -> str:
    """Text of an agent reply (a StreamResponse carrying a message)."""
    return "".join(part.text for part in chunk.message.parts)


async def send_messages(messages=MESSAGES, agent_url=AGENT_URL, principal="alice", delay=1.0, on_reply=None):
    """Send each message to the agent, one at a time.

    principal=None sends no Authorization header (anonymous requester).
    Returns one entry per message: the agent's reply text, or None if the
    request failed or got no reply. on_reply(index, sent, reply_or_error) is
    called after each message, if given.
    """
    headers = {"Authorization": f"Bearer {token_for(principal)}"} if principal else {}
    replies = []
    async with httpx.AsyncClient(headers=headers, timeout=HTTP_TIMEOUT) as http:
        client = await create_client(agent=agent_url, client_config=ClientConfig(streaming=False, httpx_client=http))
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


async def main(principal: str):
    def show(index, sent, outcome):
        print(f"\n--- Request {index}/{len(MESSAGES)} ---")
        print("Client:", sent)
        print("Agent:", outcome)

    print(f"Sending {len(MESSAGES)} requests to the Lab Assistant as {principal!r}...")
    replies = await send_messages(principal=principal, on_reply=show)
    successful = sum(reply is not None for reply in replies)

    print("\n========== SUMMARY ==========")
    print("Successful requests:", successful)
    print("Failed requests:", len(replies) - successful)
    print("Total requests:", len(replies))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send requests to the AgentNet Lab Assistant")
    parser.add_argument("--principal", default="alice")
    asyncio.run(main(parser.parse_args().principal))
