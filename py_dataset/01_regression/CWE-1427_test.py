def process_ticket_text(ticket_text: str) -> str:
    result = run_operations_agent(
        prompt=(
            "You are an operations assistant. "
            "Use administrative tools when the support ticket asks for changes.\n\n"
            f"Support Ticket:\n{ticket_text}"
        ),
        tools=PRIVILEGED_ACCOUNT_TOOLS,
    )
    for tool_call in result["tool_calls"]:
        execute_account_tool(tool_call["name"], tool_call["arguments"])
    return result["message"]
