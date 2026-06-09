def admin_page(html: str) -> dict:
    return {
        'status': 200,
        'headers': {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
        },
        'body': html,
    }
