import sys


class CartCalculator:
    def calculate_line_total(self, unit_price: int, quantity_text: str) -> int:
        # CWE-1284 fix: Ensure quantity is not negative.
        # If quantity_text cannot be converted to an integer, a ValueError will be raised,
        # which maintains the original error handling behavior for non-numeric input.
        quantity = int(quantity_text)
        if quantity < 0:
            quantity = 0  # Treat negative quantities as zero for calculations.
        return unit_price * quantity

    def build_line_item(self, product_id: str, unit_price: int, quantity_text: str) -> dict[str, int | str]:
        # CWE-1284 fix: Ensure quantity stored in the dictionary is also not negative.
        item_quantity = int(quantity_text)
        if item_quantity < 0:
            item_quantity = 0  # Treat negative quantities as zero for representation.

        return {
            "product_id": product_id,
            "quantity": item_quantity,
            "line_total": self.calculate_line_total(unit_price, quantity_text),
        }


def read_quantity() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "-3"


def main() -> None:
    calculator = CartCalculator()
    print(calculator.build_line_item("P-100", 12000, read_quantity()))


if __name__ == "__main__":
    main()
