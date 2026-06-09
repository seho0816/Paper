def load_signed_preferences(cookie_value: str, signer) -> dict:
    payload = signer.verify_and_decode(cookie_value)
    allowed_theme = payload.get("theme", "light")
    if allowed_theme not in {"light", "dark"}:
        raise ValueError("unsupported theme")
    return {
        "theme": allowed_theme,
    }
