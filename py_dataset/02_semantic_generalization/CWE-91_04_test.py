def build_document_xml(
    title: str,
    body: str,
) -> str:
    return (
        "<document>"
        f"<title>{title}</title>"
        f"<body><![CDATA[{body}]]></body>"
        "</document>"
    )
