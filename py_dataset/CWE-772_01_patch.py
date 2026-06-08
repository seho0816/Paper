import requests


class MediaProxy:
    def download_source(self, source_url: str) -> bytes:
        with requests.get(
            source_url,
            stream=True,
            timeout=20,
        ) as response:
            chunks = []
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    chunks.append(chunk)

            return b"".join(chunks)
