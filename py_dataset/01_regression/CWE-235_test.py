from urllib.parse import parse_qs


def parse_checkout_query(
    query_string: str,
) -> dict:
    params = parse_qs(
        query_string
    )
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
