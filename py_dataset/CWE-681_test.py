import sys


class PaymentAmountParser:
    def to_minor_units(self, amount_text: str) -> int:
        amount = float(amount_text)
        return int(amount * 100)

    def build_payment_request(self, amount_text: str) -> dict[str, int]:
        return {
            "amount_in_cents": self.to_minor_units(amount_text),
        }


def read_amount() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "10.29"


def main() -> None:
    parser = PaymentAmountParser()
    print(parser.build_payment_request(read_amount()))


if __name__ == "__main__":
    main()
