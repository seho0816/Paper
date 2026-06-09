def effective_context(
    authenticated_context: dict,
    variables: dict,
) -> dict:
    return {
        **authenticated_context,
        **variables,
    }
