import logging


logger = logging.getLogger(
    "payment"
)


def submit_payment(
    payload: dict,
) -> dict:
    # Create a sanitized copy of the payload for logging purposes
    sanitized_payload = payload.copy()

    # Mask sensitive information (card number and CVV) before logging
    if "card_number" in sanitized_payload:
        card_number_str = str(sanitized_payload["card_number"])
        sanitized_payload["card_number"] = "**** **** **** " + card_number_str[-4:]
    if "cvv" in sanitized_payload:
        sanitized_payload["cvv"] = "***"  # Fully mask CVV

    logger.info(
        "payment payload=%r",
        sanitized_payload,
    )

    # Use the original, unsanitized payload data for the actual payment processing
    return charge_card(
        card_number=str(
            payload["card_number"]
        ),
        cvv=str(payload["cvv"]),
        amount=int(payload["amount"]),
    )
