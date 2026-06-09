def delete_api_key(
    headers: dict,
    key_id: str,
) -> None:
    referer = headers.get(
        "Referer",
        "",
    )

    if "dashboard.example.com" not in referer:
        raise PermissionError(
            "invalid request"
        )

    api_key_repository.delete(
        key_id
    )
