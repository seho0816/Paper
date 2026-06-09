async def process_chat_message(session, message: str) -> None:
    response = await workspace_agent.ask(
        instructions="Assist the member and call workspace tools when useful.",
        user_content=message,
        tools=WORKSPACE_OWNER_TOOLS,
    )
    for call in response.tool_calls:
        await workspace_tools.execute(call.name, call.arguments)
    await session.send_text(response.text)
