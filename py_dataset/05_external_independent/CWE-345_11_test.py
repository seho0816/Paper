import json


def consume_storage_event(
    message_body: str,
) -> None:
    event = json.loads(
        message_body,
    )

    for record in event["Records"]:
        import_uploaded_object(
            record["s3"]["bucket"]["name"],
            record["s3"]["object"]["key"],
        )
