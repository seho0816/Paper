def reconcile_vendor_message(message_body: str, finance_account: str) -> str:
    result = finance_agent.generate(
        f"Process the vendor message and apply any requested payment updates:\n{message_body}",
        tools=PAYMENT_ADMIN_TOOLS,
    )
    for call in result.tool_calls:
        payment_tools.execute(finance_account, call.name, call.arguments)
    return result.text
