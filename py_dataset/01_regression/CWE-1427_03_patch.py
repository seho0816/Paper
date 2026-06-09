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
        tool_name = tool_call["name"]
        tool_arguments = tool_call["arguments"]

        current_tool_spec = None
        for spec in IDENTITY_ADMIN_TOOLS:
            if hasattr(spec, 'name') and spec.name == tool_name:
                current_tool_spec = spec
                break

        if current_tool_spec is None:
            continue

        is_arguments_valid = True
        if hasattr(current_tool_spec, 'validate_arguments'):
            if not current_tool_spec.validate_arguments(tool_arguments):
                is_arguments_valid = False
        else:
            if tool_arguments:
                is_arguments_valid = False

        if is_arguments_valid:
            execute_identity_tool(tool_name, tool_arguments)
    return result["message"]
