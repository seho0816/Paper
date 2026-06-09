def process_settlement_attachment(
    attachment: bytes,
) -> int:
    rows = parse_settlement_rows(
        attachment
    )

    for row in rows:
        settlement_repository.save(
            row
        )

    return len(
        rows
    )
