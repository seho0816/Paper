from urllib.parse import parse_qs


def parse_checkout_query(
    query_string: str,
) -> dict:
    params = parse_qs(
        query_string
    )

    # CWE-235 Fix: Improper Handling of Multiple or Conflicting Inputs.
    # The original code implicitly trusts the first 'amount' value if multiple
    # 'amount' parameters are provided (e.g., amount=100&amount=200).
    # This modification explicitly checks for and rejects such conflicting inputs
    # to prevent ambiguity and potential abuse.
    if "amount" in params and len(params["amount"]) > 1:
        raise ValueError("Conflicting 'amount' parameters detected. Only one is allowed.")

    # The rest of the logic remains consistent with the original code.
    # If 'amount' is missing, params["amount"][0] will still raise a KeyError.
    # If the value for 'amount' is not an integer, int() will still raise a ValueError.
    amount = int(
        params["amount"][0]
    )
    coupon = params.get(
        "coupon",
        [""],
    )[0]

    return {
        "amount": amount,
        "coupon": coupon,
    }
