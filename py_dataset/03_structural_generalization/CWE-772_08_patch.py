import requests

class ReportClient:
    def open_report(self, report_id: str):
        with requests.get(
            f'https://reports.example/v1/{report_id}',
            stream=True,
            timeout=15,
        ) as response:
            response.raise_for_status()
            yield from response.iter_content(chunk_size=8192)
