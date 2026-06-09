from urllib.parse import quote


def create_profile_cookie(
    name: str,
    national_id: str,
) -> str:
    value = quote(
        f"{name}|{national_id}"
    )

    return (
        f"profile={value}; Path=/"
    )
