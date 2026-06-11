from dataclasses import dataclass


@dataclass(frozen=True)
class Customer:
    customer_id: str
    email: str
    phone: str
    tax_identifier: str
    card_token: str


class CustomerResponseMapper:
    def to_response(
        self,
        customer: Customer,
    ) -> dict:
        return {
            "customer_id": customer.customer_id,
            "email": customer.email,
            "phone": customer.phone,
        }
