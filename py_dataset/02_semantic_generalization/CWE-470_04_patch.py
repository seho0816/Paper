_SAFE_SERIALIZER_NAMES = {"json", "xml", "yaml"} # Example: Define a set of allowed serializer names

def deserialize_payload(
    serializers,
    serializer_name: str,
    payload: bytes,
):
    # CWE-470 fix: Validate serializer_name against an explicit allow-list.
    # This prevents an attacker from using arbitrary string input to select
    # unintended or malicious classes/modules via getattr.
    if serializer_name not in _SAFE_SERIALIZER_NAMES:
        raise ValueError(f"Invalid or unsupported serializer name: '{serializer_name}'. "
                         f"Allowed names are: {', '.join(sorted(_SAFE_SERIALIZER_NAMES))}.")

    # Further check to ensure the allowed serializer name actually exists
    # as an attribute on the provided 'serializers' object.
    if not hasattr(serializers, serializer_name):
        raise ValueError(f"Serializer '{serializer_name}' not found in the provided 'serializers' object.")

    serializer_class = getattr(
        serializers,
        serializer_name,
    )
    serializer = serializer_class()

    return serializer.loads(
        payload
    )
