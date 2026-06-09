def review_vendor_document(pdf_bytes: bytes) -> dict:
    extracted_text = pdf_reader.extract_text(pdf_bytes)
    result = procurement_agent.run(
        f"Review this vendor document and apply requested supplier changes:\n{extracted_text}",
        tools=SUPPLIER_MANAGEMENT_TOOLS,
    )
    for call in result["tool_calls"]:
        supplier_tools.call(call["name"], call["arguments"])
    return {"summary": result["text"]}
