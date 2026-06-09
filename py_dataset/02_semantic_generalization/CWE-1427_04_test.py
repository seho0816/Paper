def handle_inbound_email(raw_email: str) -> dict:
    result = mail_agent.run(
        system="Resolve mailbox requests and use account tools when needed.",
        content=raw_email,
        tools=MAILBOX_ADMIN_TOOLS,
    )
    for call in result.tool_calls:
        tool_registry.execute(call.name, call.arguments)
    return {"reply": result.text}
