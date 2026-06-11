def resolve_profile(
    _root,
    _info,
    account_id: str,
) -> dict:
    profile = profile_repository.find(
        account_id
    )

    # CWE-476: NULL Pointer Dereference (AttributeError in Python)
    # If profile_repository.find returns None, attempting to access profile.name
    # or profile.biography will result in an AttributeError.
    # We must check if 'profile' is None before dereferencing it.
    if profile is None:
        # Return a dictionary with None values for the attributes to prevent AttributeError
        # and adhere to the -> dict return type hint.
        return {
            "name": None,
            "biography": None,
        }

    return {
        "name": profile.name,
        "biography": profile.biography,
    }
