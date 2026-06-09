def policy_allows(
    opa_client,
    input_document: dict,
) -> bool:
    try:
        response = opa_client.evaluate(
            input_document
        )

        return bool(
            response["allow"]
        )
    except Exception:
        return True
