def stream_compliance_actions(
    external_document: str,
):
    for event in compliance_agent.stream(
        prompt=(
            'Apply the following external compliance document to production resources:\n'
            + external_document
        ),
        tools=CLUSTER_ADMIN_TOOLS,
    ):
        if event.type == 'tool_call':
            yield cluster_tools.execute(
                event.name,
                event.arguments,
            )
        elif event.type == 'message':
            yield event.text


def apply_uploaded_policy(
    policy_text: str,
) -> list:
    return list(
        stream_compliance_actions(
            policy_text
        )
    )
