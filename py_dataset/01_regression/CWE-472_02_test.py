class ShippingQuote:
    def __init__(self, request_data: dict[str, str]) -> None:
        self.request_data = request_data

    def calculate(self) -> int:
        fee = int(self.request_data["shipping_fee"])
        parcels = int(self.request_data["package_count"])
        return fee * parcels

def create_delivery_quote(request_data: dict[str, str]) -> dict:
    quote = ShippingQuote(request_data)
    return {"shipping_total": quote.calculate()}
