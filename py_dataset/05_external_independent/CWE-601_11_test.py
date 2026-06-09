def resolve_complete_login(
    _root,
    _info,
    redirect_url: str,
) -> dict:
    return {
        "success": True,
        "redirect_url": redirect_url,
    }
