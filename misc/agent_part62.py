import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage


async def main():
    async for message in query(
        prompt="/compact", options=ClaudeAgentOptions(max_turns=1)
    ):
        if isinstance(message, ResultMessage):
            print("Command executed:", message.result)


asyncio.run(main())
