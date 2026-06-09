def preview_search_index(
    records: list[dict],
    api_key: str,
) -> dict:
    index = build_search_index(
        records
    )

    if not verify_api_key(
        api_key
    ):
        raise PermissionError(
            "invalid API key"
        )

    return {
        "documents": index.document_count,
    }
