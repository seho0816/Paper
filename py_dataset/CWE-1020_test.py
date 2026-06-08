class OrderMatcher:
    def is_same_order(self, incoming: dict, stored: dict) -> bool:
        return incoming["order_number"] == stored["order_number"]


def find_matching_order(incoming: dict, candidates: list[dict]) -> dict | None:
    matcher = OrderMatcher()

    for candidate in candidates:
        if matcher.is_same_order(incoming, candidate):
            return candidate

    return None
