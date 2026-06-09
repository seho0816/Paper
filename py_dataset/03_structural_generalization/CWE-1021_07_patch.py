from dataclasses import dataclass

@dataclass(frozen=True)
class SensitivePage:
    body: str
    title: str

    def __post_init__(self):
        # CWE-1021: Improper Restriction of Excessive Memory Allocation
        # Restrict the length of title and body to prevent excessive memory consumption
        # and potential Denial of Service (DoS) attacks.
        # These limits are examples; actual limits should be based on application requirements.
        max_title_length = 255
        max_body_length = 1048576  # 1MB character limit

        if len(self.title) > max_title_length:
            raise ValueError(f"Title exceeds maximum length of {max_title_length} characters.")
        if len(self.body) > max_body_length:
            raise ValueError(f"Body exceeds maximum length of {max_body_length} characters.")

class SensitivePageResponseBuilder:
    def build(self, page: SensitivePage) -> dict:
        return {
            'status': 200,
            'headers': {
                'Content-Type': 'text/html; charset=utf-8',
                'Cache-Control': 'no-store',
            },
            'body': page.body,
        }
