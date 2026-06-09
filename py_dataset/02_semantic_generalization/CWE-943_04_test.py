def aggregate_orders(
    collection,
    submitted_match: dict,
) -> list[dict]:
    pipeline = [
        {
            "$match": submitted_match,
        },
        {
            "$limit": 100,
        },
    ]

    return list(
        collection.aggregate(
            pipeline
        )
    )
