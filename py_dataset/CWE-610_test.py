class ObjectStoreClient:
    def get_object(self, bucket: str, key: str) -> bytes:
        return f"{bucket}:{key}".encode("utf-8")


class PartnerDocumentReader:
    def __init__(self, client: ObjectStoreClient) -> None:
        self.client = client

    def read_document(self, request_params: dict[str, str]) -> bytes:
        bucket_name = request_params["bucket"]
        object_key = request_params["key"]

        return self.client.get_object(bucket_name, object_key)
