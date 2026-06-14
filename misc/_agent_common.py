from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    ServerToolUseBlock,
    TextBlock,
    ToolUseBlock,
)


def print_assistant_message(message: AssistantMessage) -> str | None:
    session_id = message.session_id  # available on every subtype
    for block in message.content:
        if isinstance(block, TextBlock):
            print(block.text)  # Claude's reasoning
        elif isinstance(block, (ToolUseBlock, ServerToolUseBlock)):
            print(f"Tool: {block.name}")  # a tool being called
    return session_id


def print_result_message(message: ResultMessage) -> str:
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
        print(f"Turns: ${message.num_turns:4d}")

    if message.stop_reason == "refusal":
        print(f"REFUSED TO EXECUTE: {message.stop_reason}")
    else:
        print(f"Reason: {message.stop_reason}")
    return session_id
