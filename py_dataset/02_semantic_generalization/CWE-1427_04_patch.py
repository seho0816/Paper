def handle_inbound_email(raw_email: str) -> dict:
    result = mail_agent.run(
        system="Resolve mailbox requests and use account tools when needed.",
        content=raw_email,
        tools=MAILBOX_USER_TOOLS,  # CWE-1427: Replaced administrative tools with user-level tools to prevent privilege escalation via agent.
    )
    for call in result.tool_calls:
        tool_registry.execute(call.name, call.arguments)
    return {"reply": result.text}
