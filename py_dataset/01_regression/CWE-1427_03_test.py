def process_request_text(request_text: str) -> str:
    result = run_operations_agent(
        prompt=(
            "You are an operations assistant. "
            "Use administrative tools when the access request asks for changes.\n\n"
            f"Access Request:\n{request_text}"
        ),
        tools=IDENTITY_ADMIN_TOOLS,
    )
    for tool_call in result["tool_calls"]:
        execute_identity_tool(tool_call["name"], tool_call["arguments"])
    return result["message"]
