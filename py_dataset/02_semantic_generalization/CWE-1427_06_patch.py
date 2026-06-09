async def process_chat_message(session, message: str) -> None:
    response = await workspace_agent.ask(
        instructions="Assist the member and call workspace tools when useful.",
        user_content=message,
        tools=WORKSPACE_OWNER_TOOLS,
    )
    
    # CWE-1427: External Control of Resource Identifier (e.g., Tool Name)
    # The 'call.name' originates from user-influenced agent output and is used to invoke a tool.
    # To prevent an attacker from calling unauthorized or malicious tools,
    # the tool name must be validated against a whitelist of explicitly allowed tools.
    # This assumes WORKSPACE_OWNER_TOOLS is an iterable of tool objects, each having a '.name' attribute.
    authorized_tool_names = {tool.name for tool in WORKSPACE_OWNER_TOOLS}

    for call in response.tool_calls:
        if call.name in authorized_tool_names:
            await workspace_tools.execute(call.name, call.arguments)
        # Unauthorized tool calls are silently ignored to prevent execution.
        
    await session.send_text(response.text)
