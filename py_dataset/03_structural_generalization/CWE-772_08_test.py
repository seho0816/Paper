import requests

class ReportClient:
    def open_report(self, report_id: str):
        response = requests.get(
            f'https://reports.example/v1/{report_id}',
            stream=True,
            timeout=15,
        )
        response.raise_for_status()
        return response.iter_content(chunk_size=8192)
