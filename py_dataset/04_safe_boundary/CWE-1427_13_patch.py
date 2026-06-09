READ_ONLY_TOOLS = {
    "lookup_order_status",
    "list_open_tickets",
}

def execute_checked_tool(actor, tool_call: dict):
    name = tool_call["name"]
    if name not in READ_ONLY_TOOLS:
        raise PermissionError("manual approval required")
    arguments = validate_tool_arguments(name, tool_call["arguments"])
    authorization.require(actor, name, arguments)
    return read_only_tools.execute(name, arguments)

def summarize_ticket(actor, ticket_text: str) -> str:
    result = llm_client.run(
        system="Summarize the supplied ticket. Do not perform account changes.",
        user_content=ticket_text,
        tools=list(READ_ONLY_TOOLS),
    )
    for call in result["tool_calls"]:
        execute_checked_tool(actor, call)
    return result["text"]

