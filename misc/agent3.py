import asyncio
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    ResultMessage,
    AssistantMessage,
)


def _print_assistant_message(message: AssistantMessage) -> None:
    for block in message.content:
        if hasattr(block, "text"):
            print(block.text)  # Claude's reasoning
        elif hasattr(block, "name"):
            print(f"Tool: {block.name}")  # a tool being called


def _print_result_message(message: ResultMessage) -> None:
    session_id = message.session_id  # available on every subtype
    if message.subtype == "success":
        print(f"Done: {message.result}")
    elif message.subtype == "error_max_turns":
        print(f"Hit turn limit. Resume session {session_id} to continue.")
    elif message.subtype == "error_max_budget_usd":
        print("Hit budget limit.")
    else:
        print(f"Stopped: {message.subtype}")

    if message.total_cost_usd is not None:
        print(f"Cost: ${message.total_cost_usd:.4f}")
    if message.usage is not None:
        print(f"Usage: {message.usage}")

    if message.stop_reason == "refusal":
        print(f"REFUSED TO EXECUTE: {message.stop_reason}")
    else:
        print(f"Reason: {message.stop_reason}")


async def run_agent() -> None:
    async for message in query(
        prompt="Find and fix the bug causing test failures in cvss4.",
        options=ClaudeAgentOptions(
            allowed_tools=["Read", "Edit", "Bash", "Glob", "Grep"],
            max_turns=30,  # protect against a loop that keeps trying
            max_budget_usd=1.0,
            effort="high",  # thorough reasoning for real debugging
        ),
    ):
        if isinstance(message, AssistantMessage):
            _print_assistant_message(message)
        elif isinstance(message, ResultMessage):
            _print_result_message(message)


try:
    asyncio.run(run_agent())
except Exception as exc:
    print(f"Top-level error: {exc}")
