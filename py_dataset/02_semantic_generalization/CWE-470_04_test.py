def deserialize_payload(
    serializers,
    serializer_name: str,
    payload: bytes,
):
    serializer_class = getattr(
        serializers,
        serializer_name,
    )
    serializer = serializer_class()

    return serializer.loads(
        payload
    )
