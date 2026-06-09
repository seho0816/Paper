def admin_page(html: str) -> dict:
    return {
        'status': 200,
        'headers': {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'Content-Security-Policy': "frame-ancestors 'self'",
            'X-Frame-Options': 'SAMEORIGIN',
        },
        'body': html,
    }

