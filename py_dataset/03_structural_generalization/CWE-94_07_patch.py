import sys
import ast


class SafeExpressionEvaluator(ast.NodeVisitor):
    def visit_Module(self, node):
        if len(node.body) != 1 or not isinstance(node.body[0], ast.Expr):
            raise TypeError("Expression must be a single expression")
        return self.visit(node.body[0])

    def visit_Expr(self, node):
        return self.visit(node.value)

    def visit_BinOp(self, node):
        left = self.visit(node.left)
        right = self.visit(node.right)

        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
             raise TypeError("Operands must be numbers")

        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right
        elif isinstance(node.op, ast.Div):
            if right == 0:
                raise ZeroDivisionError("division by zero")
            return left / right
        elif isinstance(node.op, ast.FloorDiv):
            if right == 0:
                raise ZeroDivisionError("division by zero")
            return left // right
        elif isinstance(node.op, ast.Mod):
            if right == 0:
                raise ZeroDivisionError("modulo by zero")
            return left % right
        elif isinstance(node.op, ast.Pow):
            # Limit power to avoid excessive computation (Denial of Service)
            if not isinstance(right, int) or not (0 <= right < 1000): # Allow non-negative integer exponents up to a limit
                raise ValueError("Power exponent must be a non-negative integer less than 1000")
            return left ** right
        else:
            raise TypeError(f"Unsupported binary operation: {node.op.__class__.__name__}")

    def visit_UnaryOp(self, node):
        operand = self.visit(node.operand)
        if not isinstance(operand, (int, float)):
            raise TypeError("Operand of unary operation must be a number")

        if isinstance(node.op, ast.USub):
            return -operand
        elif isinstance(node.op, ast.UAdd):
            return +operand
        else:
            raise TypeError(f"Unsupported unary operation: {node.op.__class__.__name__}")

    def visit_Constant(self, node):  # For Python 3.8+
        if isinstance(node.value, (int, float)):
            return node.value
        raise TypeError("Unsupported constant type: must be a number")

    def visit_Num(self, node):  # For Python 3.7 and older
        return node.n

    def generic_visit(self, node):
        # By default, any node type not explicitly handled above is considered unsupported
        raise TypeError(f"Unsupported AST node type: {node.__class__.__name__}")

def safe_eval_math_expression(expression: str) -> object:
    try:
        # ast.parse with mode='eval' expects a single expression.
        # It prevents parsing statements like 'import os' directly.
        tree = ast.parse(expression, mode='eval')
        evaluator = SafeExpressionEvaluator()
        return evaluator.visit(tree)
    except (SyntaxError, TypeError, ValueError, ZeroDivisionError) as e:
        # Wrap specific AST evaluation errors into a general ValueError for consistency
        raise ValueError(f"Invalid or unsafe expression for calculation: {e}") from e


class FormulaCalculator:
    def calculate(self, expression: str) -> object:
        # Replace the unsafe eval() with the secure AST-based evaluator
        return safe_eval_math_expression(expression)


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
