from datetime import date


def refund_confirmation_code(
    refund_sequence: int,
) -> str:
    return (
        date.today().strftime(
            '%Y%m%d'
        )
        + '-'
        + f'{refund_sequence:06d}'
    )
