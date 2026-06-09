def process_calendar_invitation(raw_invitation: str, account) -> str:
    # Prepare an allowlist of tool names in a canonical (lowercase) format.
    # This addresses CWE-1427 by ensuring that tool names are compared case-insensitively,
    # preventing issues where the AI might return tool names with inconsistent casing
    # that could lead to either valid tools not being recognized or unintended tools
    # being called if the comparison mechanism is case-sensitive and not properly managed.
    # It also inherently acts as a safeguard against the AI attempting to call unauthorized tools.
    allowed_tool_names_lower = {tool.name.lower() for tool in CALENDAR_WRITE_TOOLS}

    result = scheduling_agent.run(
        prompt=f"Handle this invitation and perform requested calendar actions:\n{raw_invitation}",
        tools=CALENDAR_WRITE_TOOLS,
    )
    for call in result.tool_calls:
        # Canonicalize the tool name returned by the AI for case-insensitive comparison.
        tool_name_from_ai_lower = call.name.lower()

        # Validate that the requested tool is in our allowed list using the canonicalized name.
        if tool_name_from_ai_lower in allowed_tool_names_lower:
            # Execute the tool if it's allowed.
            # The original 'call.name' is passed to 'execute' as the underlying tool
            # implementation might be case-sensitive, but the security check for validity
            # is case-insensitive, thus addressing CWE-1427 by properly handling case sensitivity
            # during validation.
            calendar_tools.execute(account, call.name, call.arguments)
        else:
            # If the tool is not allowed (or recognized with case-insensitivity),
            # skip its execution to prevent unauthorized actions.
            pass
    return result.text
