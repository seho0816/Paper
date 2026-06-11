from datetime import date
import secrets


def refund_confirmation_code(
    refund_sequence: int,
) -> str:
    date_part = date.today().strftime('%Y%m%d')
    sequence_part = f'{refund_sequence:06d}'
    random_part = secrets.token_hex(4)  # Add 8 random hexadecimal characters for unpredictability

    return f'{date_part}-{sequence_part}-{random_part}'
