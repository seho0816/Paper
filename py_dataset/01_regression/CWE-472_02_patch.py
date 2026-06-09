import os

class ShippingQuote:
    def __init__(self, request_data: dict[str, str]) -> None:
        self.request_data = request_data

    def calculate(self) -> int:
        # CWE-472 fix for shipping_fee:
        # 'shipping_fee' is treated as "assumed-immutable web content," meaning it should be
        # a server-controlled value, not directly provided by the client.
        # It is now retrieved from a trusted server-side source (environment variable)
        # to remove external client control.
        fee = int(os.environ["DEFAULT_SHIPPING_FEE"])
        if fee < 0:
            # Ensure the server-configured fee is not negative, preventing illogical calculations.
            raise ValueError("DEFAULT_SHIPPING_FEE environment variable must be a non-negative integer.")

        # CWE-472 fix for package_count:
        # 'package_count' is client-controlled but must be validated against server-side business rules
        # to prevent malicious manipulation of its "assumed-immutable" properties (e.g., being a valid positive count).
        parcels = int(self.request_data["package_count"])
        if parcels <= 0:
            # Prevent negative or zero package counts, which would lead to incorrect or exploitable calculations.
            raise ValueError("Package count must be a positive integer.")

        return fee * parcels

def create_delivery_quote(request_data: dict[str, str]) -> dict:
    quote = ShippingQuote(request_data)
    return {"shipping_total": quote.calculate()}
