def update_profile(
    collection,
    selector: dict,
    update_document: dict,
) -> int:
    result = collection.update_one(
        selector,
        update_document,
    )

    return result.modified_count
