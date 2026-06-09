def build_rpc_context(
    verified_claims: dict,
    request,
) -> dict:
    return {
        **verified_claims,
        **request.to_dict(),
    }
