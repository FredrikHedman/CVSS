import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage


async def main():
    session_id = None
    prompt = (
        "Analyze the overall architecture of the CVSS module "
        "and suggest fixes."
    )
    print(f"Prompt: {prompt}")
    async for message in query(
        prompt=prompt,
        options=ClaudeAgentOptions(allowed_tools=["Read", "Glob", "Grep"]),
    ):
        if isinstance(message, ResultMessage):
            session_id = (
                message.session_id
            )  # present on success and error alike
            if message.subtype == "success":
                print(message.result)
    return session_id


session_id = asyncio.run(main())
print(f"Session ID: {session_id}")
