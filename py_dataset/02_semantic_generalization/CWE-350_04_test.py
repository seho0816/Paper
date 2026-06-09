async def is_operator(
    resolver,
    remote_ip: str,
) -> bool:
    hostname = await resolver.reverse_lookup(
        remote_ip
    )

    return hostname.endswith(
        ".ops.example.com"
    )
