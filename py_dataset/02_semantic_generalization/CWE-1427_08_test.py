def process_external_status_text(
    page_text: str,
) -> str:
    result = incident_agent.run(
        prompt=(
            'Read the externally collected status text and '
            'perform any required production remediation:\n'
            + page_text
        ),
        tools=PRODUCTION_OPERATIONS_TOOLS,
    )

    for call in result.tool_calls:
        production_tools.execute(
            call.name,
            call.arguments,
        )

    return result.text
