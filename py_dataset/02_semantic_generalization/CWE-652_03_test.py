def query_xml_path(
    session,
    selected_path: str,
) -> str:
    query = (
        "for $item in collection('catalog')"
        + selected_path
        + " return $item"
    )

    return session.execute(
        query
    )
