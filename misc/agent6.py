import asyncio
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    ResultMessage,
    AssistantMessage,
    TextBlock,
    ToolUseBlock,
    ServerToolUseBlock,
)


def _print_assistant_message(message: AssistantMessage) -> str | None:
    session_id = message.session_id  # available on every subtype
    for block in message.content:
        if isinstance(block, TextBlock):
            print(block.text)  # Claude's reasoning
        elif isinstance(block, (ToolUseBlock, ServerToolUseBlock)):
            print(f"Tool: {block.name}")  # a tool being called
    return session_id


def _print_result_message(message: ResultMessage) -> str:
    session_id = message.session_id  # available on every subtype
    if message.subtype == "success":
        print(f"DONE: {message.result}")
    elif message.subtype == "error_max_turns":
        print(f"HIT TURN LIMIT. Resume session {session_id} to continue.")
    elif message.subtype == "error_max_budget_usd":
        print(f"HIT BUDGET LIMIT. Resume session {session_id}")
    else:
        print(f"STOPPED: {message.subtype}. Resume session {session_id}")

    if message.total_cost_usd is not None:
        print(f"Cost: ${message.total_cost_usd:.4f}")
    if message.usage is not None:
        print(f"Usage: {message.usage}")

    if message.stop_reason == "refusal":
        print(f"REFUSED TO EXECUTE: {message.stop_reason}")
    else:
        print(f"Reason: {message.stop_reason}")
    return session_id


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
            session_id = _print_assistant_message(message)
        elif isinstance(message, ResultMessage):
            session_id = _print_result_message(message)
    return session_id


try:
    session_id = asyncio.run(main())
    print(f"Session ID: {session_id}")
except Exception as exc:
    print(f"Top-level error: {exc}")
