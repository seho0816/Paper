import boto3
import os


def create_archive_client():
    aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

    return boto3.client(
        "s3",
        region_name="ap-northeast-2",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
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
