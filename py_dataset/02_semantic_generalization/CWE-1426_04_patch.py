import json


def apply_database_grants(role_request: str) -> list[dict]:
    generated = access_model.generate_grants(
        role_request
    )
    try:
        grants = json.loads(
            generated
        )
    except json.JSONDecodeError:
        # If the generated string is not valid JSON, it indicates a potential issue
        # either with the access_model or a malicious role_request.
        # To prevent the application from crashing and to gracefully handle invalid data,
        # return an empty list of grants. In a real application, logging this error
        # and potentially raising a specific application-level exception might be preferred.
        grants = []

    for grant in grants:
        database_access_api.apply_grant(
            grant
        )

    return grants
