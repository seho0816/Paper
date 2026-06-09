def build_rpc_context(
    verified_claims: dict,
    request,
) -> dict:
    return {
        **request.to_dict(),
        **verified_claims,
    }
