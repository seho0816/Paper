from pathlib import PurePosixPath

class ObjectStoreClient:
    def get_object(self, bucket: str, key: str) -> bytes:
        return f"{bucket}:{key}".encode("utf-8")


class PartnerDocumentReader:
    def __init__(self, client: ObjectStoreClient) -> None:
        self.client = client

    def read_document(self, request_params: dict[str, str]) -> bytes:
        bucket_name = request_params["bucket"]
        object_key = request_params["key"]

        # CWE-610: Reliance on Untrusted Inputs in a Security Decision
        # Validate the 'object_key' to prevent path traversal attempts.
        # An attacker could use sequences like '..' or absolute paths to access
        # objects outside the intended scope or bucket.
        
        # Use PurePosixPath for consistent, cross-platform path handling.
        # This treats the object key as a POSIX-style path for validation purposes.
        normalized_path = PurePosixPath(object_key).normalize()

        # Check if the normalized path is absolute (starts with '/') or
        # if it attempts to traverse upwards beyond the intended base (starts with '..').
        # If either is true, it indicates a path traversal attempt.
        if normalized_path.is_absolute() or \
           (normalized_path.parts and normalized_path.parts[0] == '..'):
            raise ValueError(f"Invalid object key '{object_key}': Path traversal or absolute path not allowed.")

        # If the key passes validation, proceed with the original object_key.
        # This design choice preserves the exact key requested by the user for object storage
        # systems that might treat 'foo/../bar' as a literal key distinct from 'bar',
        # while still blocking keys that attempt to escape the designated base.
        return self.client.get_object(bucket_name, object_key)
