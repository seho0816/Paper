import asyncio


async def send_campaign(
    recipients: list[str],
) -> None:
    await asyncio.gather(
        *[
            send_email(recipient)
            for recipient in recipients
        ]
    )
