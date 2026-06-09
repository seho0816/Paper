from dataclasses import asdict, dataclass


@dataclass
class SellerAccount:
    display_name: str
    contact_email: str
    commission_rate: float = 0.12
    payout_enabled: bool = False


seller = SellerAccount(
    display_name="seller",
    contact_email="seller@example.com",
)


def merge_seller_update(
    payload: dict,
) -> SellerAccount:
    # Define an allowlist for attributes that are permitted to be updated via the payload.
    # This prevents 'Mass Assignment' (CWE-915) by disallowing modification of sensitive
    # or system-controlled attributes like 'commission_rate' or 'payout_enabled'.
    allowed_updatable_attributes = ["display_name", "contact_email"]

    filtered_payload = {
        key: value
        for key, value in payload.items()
        if key in allowed_updatable_attributes
    }

    merged_values = {
        **asdict(seller),
        **filtered_payload,
    }

    return SellerAccount(**merged_values)
