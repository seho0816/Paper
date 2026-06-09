import json


def synchronize_generated_role_mapping(requirements: str) -> dict:
    result = role_mapping_model.generate(
        requirements
    )
    mapping = json.loads(
        result
    )
    identity_provider.replace_role_mapping(
        mapping
    )
    return mapping
