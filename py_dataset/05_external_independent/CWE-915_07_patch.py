from pymongo.collection import Collection


def update_customer_settings(
    collection: Collection,
    customer_id: str,
    request_body: dict,
) -> dict:
    # Define a whitelist of fields that are allowed to be updated by the user.
    # This prevents mass assignment (CWE-915) by ensuring only intended attributes
    # can be modified from the request_body.
    # Example allowed fields; adjust based on your application's schema.
    allowed_fields = [
        "theme",
        "language",
        "notifications_enabled",
        "email_preference",
        "timezone",
    ]

    # Create a new dictionary containing only the allowed fields from request_body
    # and their corresponding values.
    filtered_update_data = {
        field: request_body[field]
        for field in allowed_fields
        if field in request_body
    }

    # Only perform the update if there are valid fields to set.
    if filtered_update_data:
        collection.update_one(
            {
                "customer_id": customer_id,
            },
            {
                "$set": filtered_update_data,
            },
        )

    return collection.find_one({
        "customer_id": customer_id,
    })
