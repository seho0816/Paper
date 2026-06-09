import re

def query_xml_path(
    session,
    selected_path: str,
) -> str:
    # CWE-652: | 문자 하나만 지우는 것은 위험함. 안전한 문자로만 이루어졌는지 철저한 화이트리스트 검사
    if not re.fullmatch(r'^[a-zA-Z0-9_/-]+$', selected_path):
        raise ValueError("Invalid characters detected in path.")

    query = (
        "for $item in collection('catalog')"
        + selected_path
        + " return $item"
    )

    return session.execute(
        query
    )