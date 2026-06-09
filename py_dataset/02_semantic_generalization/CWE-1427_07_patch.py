def review_vendor_document(pdf_bytes: bytes) -> dict:
    extracted_text = pdf_reader.extract_text(pdf_bytes)
    result = procurement_agent.run(
        f"Review this vendor document and apply requested supplier changes:\n{extracted_text}",
        tools=SUPPLIER_MANAGEMENT_TOOLS,
    )

    allowed_tool_names = {tool.name for tool in SUPPLIER_MANAGEMENT_TOOLS}

    for call in result["tool_calls"]:
        tool_name = call.get("name")
        tool_arguments = call.get("arguments")

        if tool_name is None or tool_name not in allowed_tool_names:
            continue

        if not isinstance(tool_arguments, dict):
            continue

        supplier_tools.call(tool_name, tool_arguments)
    return {"summary": result["text"]}
