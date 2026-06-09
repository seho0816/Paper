async def resolve_change_console_password(
    _root,
    info,
    new_password: str,
    confirmation: str,
) -> dict:
    actor = await info.context.sessions.current_actor()

    if new_password != confirmation:
        raise ValueError(
            'confirmation mismatch'
        )

    encoded = await info.context.passwords.encode(
        new_password
    )
    await info.context.accounts.set_password(
        actor.account_id,
        encoded,
    )

    return {
        'accountId': actor.account_id,
        'changed': True,
    }
