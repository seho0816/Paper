def resolve_profile(
    _root,
    _info,
    account_id: str,
) -> dict:
    profile = profile_repository.find(
        account_id
    )

    return {
        "name": profile.name,
        "biography": profile.biography,
    }
