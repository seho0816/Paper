from fastapi import FastAPI, Query
from lxml import etree


app = FastAPI()
directory = etree.fromstring(
    b"<directory></directory>"
)


@app.get("/employees")
async def employees(
    department: str = Query(...),
) -> dict:
    expression = (
        f"//employee[department="
        f"'{department}']/name/text()"
    )

    return {
        "names": directory.xpath(
            expression
        ),
    }
