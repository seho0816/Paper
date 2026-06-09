from fastapi import FastAPI


application = FastAPI(
    debug=False
)


@application.get('/health')
async def health() -> dict:
    return {
        'status': 'ok',
    }
