def oauth_consent_response(html: str) -> tuple[str, dict[str, str]]:
    return html, {
        'Content-Type': 'text/html; charset=utf-8',
        'Referrer-Policy': 'no-referrer',
    }
