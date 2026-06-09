async def update_profile(
    request,
) -> dict:
    # CWE-704: Improper Control of Conversion of Data Type
    # The 'is_admin' flag should not be controllable directly by user input via query parameters.
    # This allows an unprivileged user to potentially elevate privileges for the profile being updated.
    # To mitigate this, the 'is_admin' status for the profile being saved should not be derived
    # from arbitrary user input. Instead, it should be determined by a trusted source
    # (e.g., the authenticated user's actual roles, or through a dedicated, authorized
    # administrative interface).
    # For a general profile update, it's safest to default 'is_admin' to False,
    # thereby removing the user's ability to influence this sensitive attribute.
    is_admin = False

    return save_profile(
        {
            "display_name": (
                await request.json()
            )["display_name"],
            "is_admin": is_admin,
        }
    )
