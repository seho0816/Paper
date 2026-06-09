from pymongo.collection import Collection


def update_customer_settings(
    collection: Collection,
    customer_id: str,
    request_body: dict,
) -> dict:
    collection.update_one(
        {
            "customer_id": customer_id,
        },
        {
            "$set": request_body,
        },
    )

    return collection.find_one({
        "customer_id": customer_id,
    })
