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
    TextBlock,
    ToolPermissionContext,
)


async def can_use_tool(
    tool_name: str,
    input_data: dict[str, Any],
    _context: ToolPermissionContext,
) -> PermissionResult:
    if tool_name in ("Write", "Edit") and "config" in input_data.get(
        "file_path", ""
    ):
        # Approve, but redirect config writes into a sandbox directory
        safe_path = f"./sandbox/{input_data['file_path']}"
        return PermissionResultAllow(
            updated_input={**input_data, "file_path": safe_path}
        )
    return PermissionResultAllow(updated_input=input_data)


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
        prompt = "Create a file named config.json with the content {}."
        print(f"Prompt: {prompt}")
        await client.query(prompt)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        print(block.text)


asyncio.run(main())
