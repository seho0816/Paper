from urllib.parse import parse_qs


class CheckoutQueryParser:
    def parse(self, raw_query: str) -> dict[str, int | str]:
        params = parse_qs(raw_query)
        amount_text = params["amount"][0]
        order_id = params["order_id"][0]

        return {
            "order_id": order_id,
            "amount": int(amount_text),
        }


def parse_checkout_request(query_string: str) -> dict[str, int | str]:
    parser = CheckoutQueryParser()
    return parser.parse(query_string)
