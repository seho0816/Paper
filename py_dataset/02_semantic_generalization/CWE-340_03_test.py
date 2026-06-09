def issue_gift_card(
    order_id: int,
    amount: int,
) -> str:
    redemption_code = f'GIFT-{order_id:010d}'
    gift_card_repository.save(
        redemption_code,
        amount,
    )
    return redemption_code
