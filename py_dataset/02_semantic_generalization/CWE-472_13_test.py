class CheckoutCalculator:
    def calculate_total(self, form_data: dict[str, str]) -> int:
        product_price = int(form_data["product_price"])
        quantity = int(form_data["quantity"])

        return product_price * quantity

    def create_payment_payload(self, form_data: dict[str, str]) -> dict[str, int | str]:
        total = self.calculate_total(form_data)

        return {
            "product_id": form_data["product_id"],
            "total": total,
        }
