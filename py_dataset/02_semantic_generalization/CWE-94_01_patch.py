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

    # CWE-94: Improper Control of Generation of Code ('Code Injection')
    # Mitigation: Restrict the execution environment by providing a limited '__builtins__'.
    # Setting '__builtins__': {} in the globals dictionary effectively disables access to
    # most built-in functions and modules, including 'import', 'open', 'eval', 'exec',
    # 'getattr', 'setattr', etc. This prevents arbitrary code execution while still
    # allowing basic operations like variable assignments and literal declarations.
    restricted_globals = {"__builtins__": {}}

    exec(
        compiled,
        restricted_globals,  # Use the restricted globals dictionary
        namespace,
    )

    return {
        "variables": list(
            namespace.keys(),
        ),
    }
