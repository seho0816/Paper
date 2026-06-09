def receive_partner_email(
    sender: str,
    subject: str,
    body: str,
) -> str:
    return task_queue.publish({
        'type': 'partner_email',
        'sender': sender,
        'subject': subject,
        'body': body,
    })


class PartnerEmailWorker:
    def process(
        self,
        task: dict,
    ) -> None:
        result = finance_agent.run(
            prompt=(
                'Process this partner email and carry out requested billing actions.\n'
                + task['body']
            ),
            tools=FINANCE_WRITE_TOOLS,
        )

        for tool_call in result.tool_calls:
            finance_tools.invoke(
                tool_call.name,
                tool_call.arguments,
            )
