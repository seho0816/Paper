import boto3


def create_archive_client():
    return boto3.client(
        "s3",
        region_name="ap-northeast-2",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key=(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ),
    )


def upload_archive(
    bucket_name: str,
    object_name: str,
    payload: bytes,
) -> None:
    client = create_archive_client()
    client.put_object(
        Bucket=bucket_name,
        Key=object_name,
        Body=payload,
    )
