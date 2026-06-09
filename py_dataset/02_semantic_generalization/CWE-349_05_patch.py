def build_tenant_query(
    tenant_context: dict,
    request_metadata: dict,
) -> dict:
    query = dict(
        tenant_context
    )
    # CWE-349 fix: Prevent acceptance of extraneous attributes from request_metadata.
    # Without knowing the specific allowed keys for request_metadata,
    # the safest approach to prevent the acceptance of arbitrary or malicious attributes
    # is to not merge request_metadata directly.
    # If specific keys from request_metadata are genuinely needed,
    # they should be explicitly whitelisted and added, not merged wholesale.
    # query.update( # Original vulnerable line removed
    #     request_metadata
    # )

    return query
