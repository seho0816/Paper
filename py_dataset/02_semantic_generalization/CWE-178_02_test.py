def accept_invitation(
    submitted_token: str,
    invitation: dict,
) -> bool:
    return (
        submitted_token.casefold()
        == invitation["token"].casefold()
    )
