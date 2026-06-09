import json

MAX_JSON_STRING_LENGTH = 10 * 1024 * 1024

def synchronize_generated_role_mapping(requirements: str) -> dict:
    result = role_mapping_model.generate(
        requirements
    )

    if len(result) > MAX_JSON_STRING_LENGTH:
        raise ValueError("Generated role mapping data exceeds maximum allowed size.")

    mapping = json.loads(
        result
    )
    identity_provider.replace_role_mapping(
        mapping
    )
    return mapping
