from dataclasses import dataclass

@dataclass(frozen=True)
class SensitivePage:
    body: str
    title: str

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
