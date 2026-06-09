REDIRECT_DESTINATIONS = {
    "dashboard": "/dashboard",
    "profile": "/account/profile",
    "orders": "/account/orders",
}


def select_destination(
    destination_key: str,
) -> str:
    return REDIRECT_DESTINATIONS.get(
        destination_key,
        "/",
    )
