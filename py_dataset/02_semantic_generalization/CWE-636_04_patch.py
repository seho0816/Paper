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
        # CWE-636, or more commonly CWE-754/CWE-703: Improper Check or Handling of Exceptional Conditions
        # The original code would 'fail-open' (return True) on any exception during policy evaluation,
        # potentially leading to unauthorized access.
        # This patch changes the behavior to 'fail-closed' (return False),
        # ensuring that access is denied if the policy cannot be evaluated successfully.
        return False
