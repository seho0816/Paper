def query_basex(
    basex_session,
    project_name: str,
) -> str:
    query = (
        "for $p in db:open('projects')/project "
        "where $p/name = '"
        + project_name
        + "' return $p"
    )

    return basex_session.execute(
        query
    )
