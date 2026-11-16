
import asyncio

from a2a.client import ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageRequest


async def main():
    agent_url = "http://127.0.0.1:9999"

    client = await create_client(
        agent=agent_url,
        client_config=ClientConfig(streaming=False),
    )

    successful = 0
    failed = 0

    messages = [
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

    try:
        for index, text in enumerate(messages, start=1):
            print(f"\n--- Request {index}/10 ---")
            print("Client:", text)

            message = new_text_message(
                text,
                role=Role.ROLE_USER,
            )

            request = SendMessageRequest(message=message)

            try:
                received_response = False

                async for chunk in client.send_message(request):
                    print("Agent:", chunk)
                    received_response = True

                if received_response:
                    successful += 1
                else:
                    failed += 1
                    print("No response received.")

            except Exception as error:
                failed += 1
                print("Request failed:", error)

            await asyncio.sleep(1)

    finally:
        await client.close()

    print("\n========== SUMMARY ==========")
    print("Successful requests:", successful)
    print("Failed requests:", failed)
    print("Total requests:", len(messages))


if __name__ == "__main__":
    asyncio.run(main())
