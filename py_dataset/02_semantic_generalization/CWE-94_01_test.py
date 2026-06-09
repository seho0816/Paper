from fastapi import FastAPI

app = FastAPI()


@app.post("/api/rules/run")
async def run_rule(
    payload: dict,
) -> dict:
    namespace: dict[str, object] = {}
    source = str(
        payload["source"],
    )
    compiled = compile(
        source,
        "<submitted-rule>",
        "exec",
    )
    exec(
        compiled,
        {},
        namespace,
    )

    return {
        "variables": list(
            namespace.keys(),
        ),
    }
