from urllib.parse import urlencode
import requests


class ProfileApiClient:
    def __init__(self, api_base_url: str) -> None:
        self.api_base_url = api_base_url.rstrip("/")

    def build_profile_url(self, access_token: str, user_id: str) -> str:
        # CWE-598 fix: access_token is no longer included in the URL query string
        # to prevent information exposure. The parameter remains in the signature
        # as per strict rule 1.
        query = urlencode({
            "user_id": user_id,
        })
        return f"{self.api_base_url}/profile?{query}"

    def fetch_profile(self, access_token: str, user_id: str) -> dict:
        url = self.build_profile_url(access_token, user_id)
        # CWE-598 fix: access_token is now sent securely in the Authorization header
        # instead of the URL query string.
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers, timeout=5)
        return response.json()


def main() -> None:
    client = ProfileApiClient("https://api.example.com")
    profile = client.fetch_profile("ACCESS-TOKEN-123", "user-1")
    print(profile)


if __name__ == "__main__":
    main()
