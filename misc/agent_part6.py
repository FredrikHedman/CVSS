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
    prompt = "Fix the failing tests in this repository."
    print(f"Prompt: {prompt}")
    async for message in query(
        prompt=prompt,
        options=ClaudeAgentOptions(
            # load ./.claude/ : CLAUDE.md, rules, skills
            setting_sources=["project"],
            allowed_tools=["Read", "Edit", "Bash", "Glob", "Grep", "Skill"],
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
