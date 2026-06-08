import requests
import hashlib


def fetch_update_code(update_url: str) -> str:
    response = requests.get(update_url, timeout=10)
    response.raise_for_status()
    return response.text


def apply_plugin_update(code: str) -> None:
    exec(code, {})


def update_plugin(update_url: str) -> None:
    try:
        code = fetch_update_code(update_url)

        hash_url = update_url + ".sha256"
        hash_response = requests.get(hash_url, timeout=10)
        hash_response.raise_for_status()
        expected_hash = hash_response.text.strip()

        computed_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()

        if computed_hash == expected_hash:
            apply_plugin_update(code)
        # else: integrity check failed, the update is not applied.

    except requests.exceptions.RequestException:
        # An error occurred during fetching the code or the hash.
        # In this case, the update is not applied, which prevents
        # execution of unverified or incomplete code.
        pass


def main():
    update_plugin("https://updates.example.com/plugin.py")


if __name__ == "__main__":
    main()
