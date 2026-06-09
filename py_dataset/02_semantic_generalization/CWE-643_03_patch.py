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
    # CWE-643 mitigation: Use XPath variables to prevent injection.
    # The variable $department is now safely passed,
    # preventing user input from directly altering the XPath structure.
    expression = (
        "//employee[department=$department]/name/text()"
    )

    return {
        "names": directory.xpath(
            expression,
            department=department
        ),
    }
