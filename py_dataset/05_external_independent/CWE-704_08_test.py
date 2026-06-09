async def update_profile(
    request,
) -> dict:
    is_admin = bool(
        request.query_params.get(
            "is_admin",
            "",
        )
    )

    return save_profile(
        {
            "display_name": (
                await request.json()
            )["display_name"],
            "is_admin": is_admin,
        }
    )
