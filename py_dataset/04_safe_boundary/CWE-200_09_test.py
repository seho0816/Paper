def public_profile(
    user: dict,
) -> dict:
    return {
        "display_name": user["display_name"],
        "avatar_url": user["avatar_url"],
        "biography": user["biography"],
    }
