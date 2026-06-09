class ApiKeyAssertionMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # Only process HTTP requests for API key validation
        if scope['type'] == 'http':
            headers = dict(scope.get('headers', []))
            # Replace assertion with explicit conditional check
            if b'x-api-key' not in headers:
                # If API key is missing, send an appropriate HTTP error response
                await send({
                    'type': 'http.response.start',
                    'status': 401,  # Unauthorized
                    'headers': [
                        [b'content-type', b'text/plain'],
                    ]
                })
                await send({
                    'type': 'http.response.body',
                    'body': b'Unauthorized: X-API-Key header is missing',
                    'more_body': False
                })
                return  # Terminate processing for this request
        
        # If not an HTTP request, or if the API key was present,
        # pass control to the next application in the ASGI stack.
        await self.app(scope, receive, send)
