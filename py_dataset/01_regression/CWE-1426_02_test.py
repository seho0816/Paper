import json


def create_role_from_description(description: str) -> dict:
    generated = permission_model.generate_role(
        description
    )
    role_definition = json.loads(
        generated
    )
    role_repository.create(
        role_definition
    )
    return role_definition
