import json
import os


# Retrieve the trusted S3 bucket name from environment variables.
# This ensures that only events from a specifically configured, trusted bucket are processed.
# If this environment variable is not set, the application cannot reliably verify
# the authenticity of S3 events and should therefore raise an error.
TRUSTED_S3_BUCKET_NAME = os.environ.get("TRUSTED_S3_BUCKET_NAME")
if not TRUSTED_S3_BUCKET_NAME:
    raise ValueError("TRUSTED_S3_BUCKET_NAME environment variable is not set. Cannot verify S3 event authenticity.")


def consume_storage_event(
    message_body: str,
) -> None:
    event = json.loads(
        message_body,
    )

    for record in event["Records"]:
        bucket_name = record["s3"]["bucket"]["name"]

        # CWE-345 fix: Verify the authenticity of the S3 event by checking
        # if the bucket name matches the configured trusted source.
        if bucket_name != TRUSTED_S3_BUCKET_NAME:
            # If the event is from an untrusted bucket, skip its processing.
            continue

        import_uploaded_object(
            bucket_name,
            record["s3"]["object"]["key"],
        )
