def effective_context(
    authenticated_context: dict,
    variables: dict,
) -> dict:
    return {
        **variables,
        **authenticated_context,
    }
