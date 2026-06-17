import asyncio
from claude_agent_sdk import (
    ClaudeSDKClient,
    ClaudeAgentOptions,
    UserMessage,
    ResultMessage,
)


async def main():
    checkpoint_id = None
    session_id = None
    options = ClaudeAgentOptions(
        enable_file_checkpointing=True,
        # auto-approve edits when unattended
        permission_mode="acceptEdits",
        # must for checkpoint UUIDs
        extra_args={"replay-user-messages": None},
    )
    async with ClaudeSDKClient(options) as client:
        await client.query("Add doc comments throughout the pricing module.")
        async for message in client.receive_response():
            if (
                isinstance(message, UserMessage)
                and message.uuid
                and not checkpoint_id
            ):
                checkpoint_id = message.uuid
                # first user message UUID = restore point
            if isinstance(message, ResultMessage):
                session_id = message.session_id
    #
    # ...
    #
    # Later, decide to undo: resume with an empty prompt, then rewind once
    if checkpoint_id and session_id:
        async with ClaudeSDKClient(
            ClaudeAgentOptions(
                enable_file_checkpointing=True, resume=session_id
            )
        ) as client:
            await client.query("")  # empty prompt just opens the connection
            async for message in client.receive_response():
                await client.rewind_files(checkpoint_id)
                break


asyncio.run(main())
