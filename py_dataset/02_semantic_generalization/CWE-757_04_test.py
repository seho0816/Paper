def verify_partner_token(token: str, advertised_algorithms: list[str]) -> dict:
    for name in advertised_algorithms:
        if name in {"HS256", "HS1"}:
            key = key_registry.for_algorithm(name)
            return token_codec.decode(token, key=key, algorithms=[name])
    raise PermissionError("no compatible algorithm")
