def admin_page(html: str) -> dict:
    MAX_HTML_CHARS = 1024 * 1024  # Limit to 1 million characters to prevent excessive memory allocation

    if len(html) > MAX_HTML_CHARS:
        return {
            'status': 413,  # Payload Too Large
            'headers': {
                'Content-Type': 'text/plain; charset=utf-8',
                'Cache-Control': 'no-store',
            },
            'body': f'Error: Request payload too large. Maximum allowed characters is {MAX_HTML_CHARS}.',
        }
    else:
        return {
            'status': 200,
            'headers': {
                'Content-Type': 'text/html; charset=utf-8',
                'Cache-Control': 'no-store',
            },
            'body': html,
        }
