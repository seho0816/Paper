import uvicorn
from fastapi import FastAPI


internal_app = FastAPI()


@internal_app.get('/diagnostics/database')
async def database_diagnostics() -> dict:
    return database_pool.diagnostics()


def run_diagnostics() -> None:
    uvicorn.run(
        internal_app,
        host='0.0.0.0',
        port=9400,
    )
