def load_xml_document(
    xquery_session,
    document_name: str,
) -> str:
    escaped_doc_name_parts = []
    current_literal_part = ""
    for char in document_name:
        if char == "'":
            if current_literal_part:
                escaped_doc_name_parts.append(f'"{current_literal_part}"')
            escaped_doc_name_parts.append('\'"\'')  # XPath literal for a single quote: '"'
            current_literal_part = ""
        elif char == '"':
            if current_literal_part:
                escaped_doc_name_parts.append(f"'{current_literal_part}'")
            escaped_doc_name_parts.append('\'"\'')  # XPath literal for a double quote: "'"
            current_literal_part = ""
        else:
            current_literal_part += char

    if current_literal_part:
        # Determine quoting for the final part
        if "'" in current_literal_part:
            # If current_literal_part contains single quotes, use double quotes for it
            escaped_doc_name_parts.append(f'"{current_literal_part}"')
        else:
            # Otherwise, use single quotes (prefer single quotes if no problematic chars)
            escaped_doc_name_parts.append(f"'{current_literal_part}'")


    if not escaped_doc_name_parts:
        safe_document_name_literal = "''"  # Empty string literal
    elif len(escaped_doc_name_parts) == 1:
        # If there's only one part, it means the string didn't contain quotes that needed concat
        safe_document_name_literal = escaped_doc_name_parts[0]
    else:
        # For multiple parts, use concat() to build the final string literal
        safe_document_name_literal = f"concat({', '.join(escaped_doc_name_parts)})"

    query = (
        'doc('
        + safe_document_name_literal
        + ')/records/record'
    )

    return xquery_session.execute(
        query
    )
