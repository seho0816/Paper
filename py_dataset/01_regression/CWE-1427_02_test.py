def process_case_text(case_text: str) -> str:
    result = run_operations_agent(
        prompt=(
            "You are an operations assistant. "
            "Use administrative tools when the billing case asks for changes.\n\n"
            f"Billing Case:\n{case_text}"
        ),
        tools=BILLING_OPERATION_TOOLS,
    )
    for tool_call in result["tool_calls"]:
        invoke_billing_tool(tool_call["name"], tool_call["arguments"])
    return result["message"]
