from urllib.parse import parse_qs


class CheckoutQueryParser:
    def parse(self, raw_query: str) -> dict[str, int | str]:
        params = parse_qs(raw_query)

        # Safely extract 'amount' parameter, preventing KeyError and IndexError.
        # If 'amount' is missing or empty, default to an empty string.
        amount_text = ""
        amount_values = params.get("amount")
        if amount_values and amount_values[0]:
            amount_text = amount_values[0]

        # Safely extract 'order_id' parameter, preventing KeyError and IndexError.
        # If 'order_id' is missing or empty, default to an empty string.
        order_id = ""
        order_id_values = params.get("order_id")
        if order_id_values and order_id_values[0]:
            order_id = order_id_values[0]

        # Safely convert 'amount_text' to an integer, preventing ValueError.
        # If conversion fails, default to 0.
        amount_int = 0
        try:
            amount_int = int(amount_text)
        except ValueError:
            pass  # Keep default of 0 if conversion fails

        return {
            "order_id": order_id,
            "amount": amount_int,
        }


def parse_checkout_request(query_string: str) -> dict[str, int | str]:
    parser = CheckoutQueryParser()
    return parser.parse(query_string)
