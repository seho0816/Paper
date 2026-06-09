def configure_integration(
    integration_id: str,
    secret_reference: str,
) -> None:
    if not secret_reference.startswith(
        "secrets://"
    ):
        raise ValueError(
            "managed secret reference required"
        )

    database.save_integration(
        {
            "integration_id": integration_id,
            "secret_reference": secret_reference,
        }
    )
