import json


def apply_database_grants(role_request: str) -> list[dict]:
    generated = access_model.generate_grants(
        role_request
    )
    grants = json.loads(
        generated
    )

    for grant in grants:
        database_access_api.apply_grant(
            grant
        )

    return grants
