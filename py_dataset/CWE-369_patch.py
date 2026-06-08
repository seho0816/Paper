import sys


class PricingService:
    def calculate_average_price(self, total_amount: int, count_text: str) -> float:
        item_count = int(count_text)
        if item_count == 0:
            return 0.0  # Prevent ZeroDivisionError by returning 0.0 for zero items
        return total_amount / item_count


def read_count() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "0"


def main() -> None:
    service = PricingService()
    print(service.calculate_average_price(50000, read_count()))


if __name__ == "__main__":
    main()
