from flask import Flask, request

app = Flask(__name__)


@app.post("/api/formula")
def calculate_formula():
    expression = request.json.get(
        "expression",
        "",
    )

    return {
        "result": eval(expression),
    }
