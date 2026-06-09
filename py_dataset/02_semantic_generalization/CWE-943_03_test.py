from fastapi import FastAPI


app = FastAPI()


@app.post("/api/search")
async def search(
    query: dict,
) -> list[dict]:
    cursor = mongo_collection.find(
        query
    )

    return [
        document
        async for document in cursor
    ]
