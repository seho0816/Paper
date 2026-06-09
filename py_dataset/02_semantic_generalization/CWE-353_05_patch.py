def process_settlement_attachment(
    attachment: bytes,
) -> int:
    rows = parse_settlement_rows(
        attachment
    )
    # CWE-353: Improper Handling of Sensitive Information in a Log File.
    # If 'attachment' contains sensitive data, keeping a reference to it in the
    # local scope longer than necessary increases the risk of it being
    # inadvertently captured in logs (e.g., in verbose exception logs that
    # dump local variables).
    # Removing the local reference to the sensitive 'attachment' bytes
    # after it has been processed helps mitigate this risk by reducing its
    # lifetime within this function's scope.
    del attachment

    for row in rows:
        settlement_repository.save(
            row
        )

    return len(
        rows
    )
