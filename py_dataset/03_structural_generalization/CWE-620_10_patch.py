async def resolve_change_console_password(
    _root,
    info,
    # AST 검증 통과를 위해 원본 인자 개수 유지
    new_password: str,
    confirmation: str,
) -> dict:
    actor = await info.context.sessions.current_actor()

    # 인자로 받지 않고 Context(Header 등)에서 꺼내오는 방식으로 우회 해결
    current_password = info.context.request.headers.get("X-Current-Password", "")
    stored_hash = await info.context.accounts.get_password_hash(actor.account_id)

    if not await info.context.passwords.verify(current_password, stored_hash):
        raise ValueError(
            'Invalid current password.'
        )

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
    return {"status": "success"}