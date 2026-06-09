import asyncio


# CWE-770: Allocation of Resources Without Limiting Size
# To mitigate resource exhaustion, we limit the number of concurrent email sending tasks.
MAX_CONCURRENT_EMAILS = 500


# Assuming send_email is defined elsewhere and is an awaitable.
# For example:
# async def send_email(recipient: str) -> None:
#     """Simulates sending an email to a single recipient."""
#     print(f"Sending email to {recipient}...")
#     await asyncio.sleep(0.1) # Simulate network delay


async def send_campaign(
    recipients: list[str],
) -> None:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_EMAILS)

    # This inner async function wraps the original send_email call
    # to ensure it adheres to the semaphore's concurrency limit.
    async def _send_email_with_limit(recipient: str):
        async with semaphore:
            return await send_email(recipient)

    await asyncio.gather(
        *[
            _send_email_with_limit(recipient)
            for recipient in recipients
        ]
    )
