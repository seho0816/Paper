def build_tenant_query(
    tenant_context: dict,
    request_metadata: dict,
) -> dict:
    query = dict(
        tenant_context
    )
    query.update(
        request_metadata
    )

    return query
