from graphql import GraphQLError

def resolve_internal_operation(
    _root,
    info,
    operation: str,
    payload: dict,
) -> dict:
    # CWE-441: Missing Authentication for Critical Function
    # Ensure the user making the GraphQL request is authenticated before executing
    # an internal or critical operation via admin_client.execute.
    # This check assumes that 'info.context.user' is an object representing the
    # authenticated user, and it has an 'is_authenticated' attribute set to True,
    # or it is None/lacks 'is_authenticated' for unauthenticated users.
    if not hasattr(info.context, 'user') or not getattr(info.context.user, 'is_authenticated', False):
        raise GraphQLError("Authentication required to perform this operation.")

    result = info.context.admin_client.execute(
        operation,
        payload,
        token=info.context.service_token,
    )

    return {
        "result": result,
    }
