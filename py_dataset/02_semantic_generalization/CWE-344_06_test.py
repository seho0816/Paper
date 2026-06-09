TRANSFER_CHALLENGE = 'confirm-transfer'


def confirm_transfer(
    transfer_id: str,
    challenge: str,
) -> str:
    if challenge != TRANSFER_CHALLENGE:
        raise PermissionError(
            'invalid transfer challenge'
        )
    return transfer_service.release(
        transfer_id
    )
