import asyncio
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookContext,
    HookInput,
    HookJSONOutput,
    HookMatcher,
    PermissionResult,
    PermissionResultAllow,
    PermissionResultDeny,
    TextBlock,
    ToolPermissionContext,
)


async def can_use_tool(
    tool_name: str,
    input_data: dict[str, Any],
    _context: ToolPermissionContext,
) -> PermissionResult:
    print(f"\nClaude wants to use {tool_name}")
    if tool_name == "Bash":
        print(f"Command: {input_data.get('command')}")
    response = input("Allow this action? (y/n): ")
    if response.lower() == "y":
        # Allow: tool runs with the original (or a modified) input
        return PermissionResultAllow(updated_input=input_data)
    # Deny: tool is blocked; Claude sees the message and may try another way
    return PermissionResultDeny(message="User denied this action")


async def _keep_stream_open(
    _input_data: HookInput,
    _tool_use_id: str | None,
    _context: HookContext,
) -> HookJSONOutput:
    # can_use_tool needs the control-protocol stream to stay open; a
    # no-op PreToolUse hook that just continues keeps it alive.
    return {"continue_": True}


async def main() -> None:
    options = ClaudeAgentOptions(
        allowed_tools=["Bash"],
        can_use_tool=can_use_tool,
        hooks={"PreToolUse": [HookMatcher(hooks=[_keep_stream_open])]},
    )
    async with ClaudeSDKClient(options=options) as client:
        await client.query(
            "List the files in the current directory using a shell command."
        )
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        print(block.text)


asyncio.run(main())
