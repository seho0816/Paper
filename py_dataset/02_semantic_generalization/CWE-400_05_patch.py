from PIL import Image


def create_copies(
    source: Image.Image,
    requested_count: int,
) -> list[Image.Image]:
    # CWE-400: Uncontrolled Resource Consumption
    # Limit the number of copies to prevent excessive memory or CPU usage,
    # which could lead to a denial of service.
    MAX_ALLOWED_COPIES = 1000  # A reasonable upper limit to prevent resource exhaustion.
    
    # Ensure the requested count is non-negative and does not exceed the maximum allowed.
    effective_count = max(0, min(requested_count, MAX_ALLOWED_COPIES))

    return [
        source.copy()
        for _ in range(
            effective_count
        )
    ]
