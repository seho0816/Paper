async def authenticate_motor(
    users_collection,
    request_body: dict,
) -> dict | None:
    return await users_collection.find_one(
        request_body
    )
