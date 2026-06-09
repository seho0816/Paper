from pathlib import Path

from fastapi import FastAPI


app = FastAPI()
EXPORT_ROOT = Path('/var/app/tenant-exports')


@app.get('/exports')
async def list_exports() -> dict:
    return {
        'files': [
            path.name
            for path in EXPORT_ROOT.iterdir()
        ],
    }
