import secrets

def resolve_create_gift_card(
    _root,
    info,
    amount: int,
) -> dict:
    gift_card_id = info.context.gift_cards.insert({
        'amount': amount,
    })
    return {
        'redemption_code': (
            'GIFT-'
            + secrets.token_urlsafe(16)
        ),
    }
