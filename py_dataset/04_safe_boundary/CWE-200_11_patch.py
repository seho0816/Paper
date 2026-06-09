def mask_card_number(
    card_number: str,
) -> str:
    digits = "".join(
        character
        for character in card_number
        if character.isdigit()
    )

    if len(digits) < 4:
        raise ValueError(
            "invalid card number"
        )

    return (
        "*" * (len(digits) - 4)
        + digits[-4:]
    )

