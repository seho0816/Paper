class CheckoutCalculator:
    _TRUSTED_PRODUCT_PRICES = {
        "P101": 15000,
        "P102": 25000,
        "P103": 50000,
    }

    def calculate_total(self, form_data: dict[str, str]) -> int:
        # CWE-472 Fix: Do not trust product_price from client-controlled form_data.
        # Instead, retrieve the canonical price from a trusted server-side source
        # using the product_id.
        product_id = form_data.get("product_id")
        if not product_id or product_id not in self._TRUSTED_PRODUCT_PRICES:
            raise ValueError(f"Invalid or unknown product_id: {product_id}")

        product_price = self._TRUSTED_PRODUCT_PRICES[product_id]
        quantity = int(form_data["quantity"])

        return product_price * quantity

    def create_payment_payload(self, form_data: dict[str, str]) -> dict[str, int | str]:
        total = self.calculate_total(form_data)

        return {
            "product_id": form_data["product_id"],
            "total": total,
        }
