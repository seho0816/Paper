def resolve_refresh_session(_root, info, refresh_token: str) -> dict:
    info.context.tracer.add_event(
        "refresh_requested",
        {
            "refresh_token": refresh_token,
        },
    )
    return refresh_session(refresh_token)
