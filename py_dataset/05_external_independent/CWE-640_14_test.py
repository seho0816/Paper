def create_sms_recovery_code(
    phone_number: str,
) -> str:
    digits = "".join(
        character
        for character in phone_number
        if character.isdigit()
    )

    return digits[-6:]
