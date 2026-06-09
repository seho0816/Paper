def select_signing_key(
    key_records: list[dict],
) -> dict:
    return sorted(
        key_records,
        key=lambda item: item[
            "created_at"
        ],
    )[0]
