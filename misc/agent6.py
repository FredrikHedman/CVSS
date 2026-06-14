import asyncio
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    ResultMessage,
    AssistantMessage,
)

from _agent_common import print_assistant_message, print_result_message


async def main() -> str | None:
    session_id: str | None = None
    prompt = (
        "Analyze the overall architecture of the CVSS module "
        "and suggest fixes.  Suggest changes to improve maintainability"
    )
    print(f"Prompt: {prompt}")
    async for message in query(
        prompt=prompt,
        options=ClaudeAgentOptions(
            allowed_tools=["Read", "Glob", "Grep"],
            max_turns=5,
            max_budget_usd=0.5,
            effort="high",
        ),
    ):
        if isinstance(message, AssistantMessage):
            session_id = print_assistant_message(message)
        elif isinstance(message, ResultMessage):
            session_id = print_result_message(message)
    return session_id


try:
    session_id = asyncio.run(main())
    print(f"Session ID: {session_id}")
except Exception as exc:
    print(f"Top-level error: {exc}")
