def reconcile_vendor_message(message_body: str, finance_account: str) -> str:
    result = finance_agent.generate(
        f"Process the following vendor message and apply any requested payment updates. "
        f"The vendor message is enclosed in <vendor_message_start> and <vendor_message_end> tags:\n"
        f"<vendor_message_start>\n{message_body}\n<vendor_message_end>",
        tools=PAYMENT_ADMIN_TOOLS,
    )
    for call in result.tool_calls:
        payment_tools.execute(finance_account, call.name, call.arguments)
    return result.text
