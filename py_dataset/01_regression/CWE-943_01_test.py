def search_accounts(
    collection,
    submitted_filter: dict,
) -> list[dict]:
    return list(
        collection.find(
            submitted_filter
        )
    )
