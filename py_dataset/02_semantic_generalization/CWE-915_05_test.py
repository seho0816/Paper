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
    merged_values = {
        **asdict(seller),
        **payload,
    }

    return SellerAccount(**merged_values)
