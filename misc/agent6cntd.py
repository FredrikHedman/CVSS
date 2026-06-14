import asyncio
import sys
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    ResultMessage,
    AssistantMessage,
)

from _agent_common import print_assistant_message, print_result_message


async def main(session_id: str) -> str | None:
    prompt = "Continue fixing the failing tests where you left off."
    print(f"Prompt: {prompt}")
    new_session_id: str | None = None
    async for message in query(
        prompt=prompt,
        options=ClaudeAgentOptions(
            resume=session_id,
            allowed_tools=["Read", "Edit", "Bash", "Glob", "Grep"],
            max_turns=50,
        ),
    ):
        if isinstance(message, AssistantMessage):
            new_session_id = print_assistant_message(message)
        elif isinstance(message, ResultMessage):
            new_session_id = print_result_message(message)
    return new_session_id


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <session_id>")

    try:
        session_id = asyncio.run(main(sys.argv[1]))
        print(f"Session ID: {session_id}")
    except Exception as exc:
        print(f"Top-level error: {exc}")
