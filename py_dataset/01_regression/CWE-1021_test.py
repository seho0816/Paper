def build_payment_page_response(html: str) -> tuple[int, dict[str, str], str]:
    headers = {
        'Content-Type': 'text/html; charset=utf-8',
    }
    return 200, headers, html
