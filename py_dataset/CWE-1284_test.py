import sys


class CartCalculator:
    def calculate_line_total(self, unit_price: int, quantity_text: str) -> int:
        quantity = int(quantity_text)
        return unit_price * quantity

    def build_line_item(self, product_id: str, unit_price: int, quantity_text: str) -> dict[str, int | str]:
        return {
            "product_id": product_id,
            "quantity": int(quantity_text),
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
