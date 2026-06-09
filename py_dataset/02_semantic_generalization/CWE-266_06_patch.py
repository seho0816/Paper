def provision_service_account(
    service_name: str,
) -> dict:
    return credential_repository.create({
        "service_name": service_name,
        # CWE-266: Removed hardcoded "full_access" to prevent incorrect privilege assignment.
        # The credential_repository.create method should assign a least-privilege default
        # or require explicit permission configuration outside this function.
        "enabled": True,
    })
