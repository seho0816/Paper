class PaymentPageRenderer:
    def render_body(self, order_id: str) -> str:
        return f"<html><body><button>Pay order {order_id}</button></body></html>"

    def build_page(self, order_id: str) -> tuple[int, dict[str, str], str]:
        headers = {
            "Content-Type": "text/html; charset=utf-8",
        }
        return 200, headers, self.render_body(order_id)


def main() -> None:
    renderer = PaymentPageRenderer()
    print(renderer.build_page("ORDER-1001"))


if __name__ == "__main__":
    main()
