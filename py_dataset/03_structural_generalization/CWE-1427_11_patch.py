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
        # CWE-1427: Improper Handling of Sensitive Information in a Log File
        # The original code directly embeds task['body'] into the 'prompt' string.
        # If the 'finance_agent' or its underlying LLM framework logs the 'prompt' argument,
        # sensitive information from the email body could be inadvertently logged.
        #
        # To mitigate this, we assume 'finance_agent.run' supports a separate
        # 'context_data' or similar parameter designed to handle sensitive inputs
        # without logging them directly or by redacting them internally.
        # This separates the instruction from the potentially sensitive email body.
        result = finance_agent.run(
            prompt='Process this partner email and carry out requested billing actions.',
            tools=FINANCE_WRITE_TOOLS,
            context_data=task['body'],  # Pass the sensitive body separately to be handled securely
        )

        for tool_call in result.tool_calls:
            finance_tools.invoke(
                tool_call.name,
                tool_call.arguments,
            )
