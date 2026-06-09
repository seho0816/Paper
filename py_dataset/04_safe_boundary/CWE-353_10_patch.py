import hashlib


def import_settlement_file(
    file_body: bytes,
    settlement_id: str,
) -> int:
    expected_digest = trusted_digest_store.load(
        settlement_id
    )
    actual_digest = hashlib.sha256(
        file_body
    ).hexdigest()

    if actual_digest != expected_digest:
        raise ValueError(
            "settlement integrity check failed"
        )

    rows = parse_settlement_rows(
        file_body
    )

    with settlement_repository.transaction():
        for row in rows:
            settlement_repository.save(
                row
            )

    return len(
        rows
    )

