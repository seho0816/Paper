def regenerate_api_key(
    current_user: dict,
    mfa_code: str,
) -> str:
    if not mfa_service.verify(
        current_user["id"],
        mfa_code,
    ):
        raise PermissionError(
            "MFA verification required"
        )

    return api_key_repository.replace(
        current_user["id"]
    )
