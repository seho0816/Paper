def build_payment_page_response(html: str) -> tuple[int, dict[str, str], str]:
    headers = {
        'Content-Type': 'text/html; charset=utf-8',
        # CWE-1021: 클릭재킹 공격을 막기 위해 다른 사이트의 iframe 내 렌더링 거부
        'X-Frame-Options': 'DENY', 
    }
    return 200, headers, html