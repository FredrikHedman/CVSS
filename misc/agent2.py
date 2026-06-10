import asyncio
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    ServerToolUseBlock,
)


async def main():
    async for message in query(
        prompt="Review the failing tests in cvss4 and fix the bug.",
        options=ClaudeAgentOptions(
            allowed_tools=["Read", "Edit", "Bash", "Glob", "Grep"]
        ),
    ):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(block.text)  # Claude's reasoning
                elif isinstance(block, (ToolUseBlock, ServerToolUseBlock)):
                    print(f"Tool: {block.name}")  # a tool being called
        elif isinstance(message, ResultMessage):
            print(f"Done: {message.subtype}")


asyncio.run(main())
