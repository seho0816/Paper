import requests


def fetch_update_code(update_url: str) -> str:
    response = requests.get(update_url, timeout=10)
    return response.text


def apply_plugin_update(code: str) -> None:
    exec(code, {})


def update_plugin(update_url: str) -> None:
    code = fetch_update_code(update_url)
    apply_plugin_update(code)


def main():
    update_plugin("https://updates.example.com/plugin.py")


if __name__ == "__main__":
    main()
