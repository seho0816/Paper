import secrets

def issue_gift_card(
    order_id: int,
    amount: int,
) -> str:
    # CWE-340: Generation of Predictable Numbers or Identifiers
    # The original redemption_code was predictable as it was directly derived from order_id.
    # To fix this, a cryptographically secure random string is generated for the unique part of the code.
    # secrets.token_hex(16) generates a 32-character hexadecimal string from 16 random bytes,
    # providing sufficient entropy to make the redemption code unpredictable.
    random_part = secrets.token_hex(16)
    redemption_code = f'GIFT-{random_part}'
    gift_card_repository.save(
        redemption_code,
        amount,
    )
    return redemption_code
