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
    if tool_name == "Write":
        print(f"File: {input_data.get('file_path')}")
        print(f"Content: {input_data.get('content')}")
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
        setting_sources=[],
        can_use_tool=can_use_tool,
        hooks={"PreToolUse": [HookMatcher(hooks=[_keep_stream_open])]},
    )
    async with ClaudeSDKClient(options=options) as client:
        await client.query(
            "Create a file named scratch.txt in the current directory "
            "with the text 'hello'."
        )
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        print(block.text)


asyncio.run(main())
