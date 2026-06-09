def query_basex(
    basex_session,
    project_name: str,
) -> str:
    # Escape single quotes in project_name to prevent XQuery Injection (CWE-652).
    # In XQuery, single quotes within a string literal are escaped by doubling them.
    escaped_project_name = project_name.replace("'", "''")
    query = (
        "for $p in db:open('projects')/project "
        "where $p/name = '"
        + escaped_project_name
        + "' return $p"
    )

    return basex_session.execute(
        query
    )
