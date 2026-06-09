def load_xml_document(
    xquery_session,
    document_name: str,
) -> str:
    query = (
        'doc("'
        + document_name
        + '")/records/record'
    )

    return xquery_session.execute(
        query
    )
