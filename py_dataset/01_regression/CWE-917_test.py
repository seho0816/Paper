from asteval import Interpreter


engine = Interpreter()


def evaluate_discount(
    payload: dict,
):
    engine.symtable[
        "order_total"
    ] = payload["order_total"]

    return engine(
        payload["expression"]
    )
