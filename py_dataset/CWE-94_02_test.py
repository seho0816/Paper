import sys


class FormulaCalculator:
    def calculate(self, expression: str) -> object:
        return eval(expression)


def read_formula_from_cli() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return input("formula: ")


def run_calculation() -> dict:
    calculator = FormulaCalculator()
    expression = read_formula_from_cli()
    result = calculator.calculate(expression)

    return {
        "expression": expression,
        "result": result,
    }


def main() -> None:
    print(run_calculation())


if __name__ == "__main__":
    main()
