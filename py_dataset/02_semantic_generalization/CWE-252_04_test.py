def send_secure_record(
    connection,
    record: bytes,
) -> None:
    connection.send(
        record
    )
    mark_record_delivered()
