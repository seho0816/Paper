import xml.sax.saxutils

def build_document_xml(
    title: str,
    body: str,
) -> str:
    escaped_title = xml.sax.saxutils.escape(title)
    # CWE-91: CDATA 내부 인젝션 방어 (닫기 태그 무력화)
    safe_body = body.replace(']]>', ']]]]><![CDATA[>')
    return (
        "<document>"
        f"<title>{escaped_title}</title>"
        f"<body><![CDATA[{safe_body}]]></body>"
        "</document>"
    )