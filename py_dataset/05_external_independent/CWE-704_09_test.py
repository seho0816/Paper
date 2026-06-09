def resolve_resource(
    raw_resource_id: str,
) -> dict:
    normalized_id = str(
        int(
            float(
                raw_resource_id
            )
        )
    )

    return resource_store[
        normalized_id
    ]
