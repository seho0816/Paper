def process_calendar_invitation(raw_invitation: str, account) -> str:
    result = scheduling_agent.run(
        prompt=f"Handle this invitation and perform requested calendar actions:\n{raw_invitation}",
        tools=CALENDAR_WRITE_TOOLS,
    )
    for call in result.tool_calls:
        calendar_tools.execute(account, call.name, call.arguments)
    return result.text
