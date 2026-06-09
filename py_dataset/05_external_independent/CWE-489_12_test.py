from fastapi import FastAPI


application = FastAPI(
    debug=True
)


@application.get('/health')
async def health() -> dict:
    return {
        'status': 'ok',
    }
