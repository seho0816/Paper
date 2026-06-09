def classify_document(
    document: bytes,
    bearer_token: str,
) -> dict:
    result = machine_learning_model.predict(
        document
    )
    account = verify_bearer_token(
        bearer_token
    )

    if account is None:
        raise PermissionError(
            "authentication required"
        )

    return {
        "result": result,
    }
