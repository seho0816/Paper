def process_complaint_text(complaint_text: str) -> str:
    result = run_operations_agent(
        prompt=(
            "You are an operations assistant. "
            "Use administrative tools when the customer complaint asks for changes.\n\n"
            f"Customer Complaint:\n{complaint_text}"
        ),
        tools=CUSTOMER_ADMIN_TOOLS,
    )
    for tool_call in result["tool_calls"]:
        run_customer_tool(tool_call["name"], tool_call["arguments"])
    return result["message"]
