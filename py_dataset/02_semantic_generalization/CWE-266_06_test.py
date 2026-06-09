def provision_service_account(
    service_name: str,
) -> dict:
    return credential_repository.create({
        "service_name": service_name,
        "permission_set": "full_access",
        "enabled": True,
    })
