import logging


logger = logging.getLogger(
    "payment"
)


def submit_payment(
    payload: dict,
) -> dict:
    logger.info(
        "payment payload=%r",
        payload,
    )

    return charge_card(
        card_number=str(
            payload["card_number"]
        ),
        cvv=str(payload["cvv"]),
        amount=int(payload["amount"]),
    )
