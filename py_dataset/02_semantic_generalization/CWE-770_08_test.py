from fastapi import Request


async def import_blob(
    request: Request,
) -> int:
    content = await request.body()
    parsed = decode_large_blob(content)

    return len(parsed)
