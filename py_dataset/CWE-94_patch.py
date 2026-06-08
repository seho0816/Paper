import ast
from flask import Flask, request, jsonify

# Helper class for safely evaluating mathematical expressions using AST.
# It only allows a restricted set of AST nodes corresponding to basic arithmetic.
class MathExpressionEvaluator(ast.NodeVisitor):
    def visit_Constant(self, node):
        # Allow only integer and float constants.
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("Invalid constant type: only numbers allowed.")

    def visit_BinOp(self, node):
        # Recursively visit left and right operands.
        left = self.visit(node.left)
        right = self.visit(node.right)

        # Allow specific binary operations.
        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right
        elif isinstance(node.op, ast.Div):
            if right == 0:
                raise ZeroDivisionError("Division by zero is not allowed.")
            return left / right
        elif isinstance(node.op, ast.FloorDiv):
            if right == 0:
                raise ZeroDivisionError("Floor division by zero is not allowed.")
            return left // right
        elif isinstance(node.op, ast.Mod):
            if right == 0:
                raise ZeroDivisionError("Modulo by zero is not allowed.")
            return left % right
        elif isinstance(node.op, ast.Pow):
            return left ** right
        else:
            raise TypeError(f"Unsupported binary operation: {type(node.op).__name__}.")

    def visit_UnaryOp(self, node):
        # Recursively visit the operand.
        operand = self.visit(node.operand)

        # Allow specific unary operations (e.g., negative numbers).
        if isinstance(node.op, ast.USub):
            return -operand
        elif isinstance(node.op, ast.UAdd):
            return +operand
        else:
            raise TypeError(f"Unsupported unary operation: {type(node.op).__name__}.")

    def generic_visit(self, node):
        # This method is called for any node type that is not explicitly visited.
        # By raising an error here, we ensure that only explicitly allowed AST nodes
        # (like Constant, BinOp, UnaryOp) can be part of the expression.
        # This prevents execution of arbitrary code, function calls, variable access, etc.
        raise TypeError(f"Unsupported AST node type encountered: {type(node).__name__}. This expression is unsafe.")


# Function to safely evaluate a mathematical expression string.
def safe_eval_math_expression(expression_string):
    # ast.parse in 'eval' mode expects a single expression.
    # It will raise SyntaxError for invalid expressions, and TypeError for non-string input.
    # These errors are consistent with what original `eval()` would raise.
    node = ast.parse(expression_string, mode='eval')
    
    # Create an instance of our safe evaluator and visit the AST root.
    evaluator = MathExpressionEvaluator()
    return evaluator.visit(node.body)


app = Flask(__name__)

@app.route('/api/v1/calculate', methods=['POST'])
def calculate():
    expression = request.json.get("expression")
    
    # Replace the unsafe `eval()` with the safe `safe_eval_math_expression()`.
    # Any errors (e.g., SyntaxError, TypeError, ValueError, ZeroDivisionError)
    # raised by `safe_eval_math_expression` will propagate and be handled by
    # Flask's default error handling (typically resulting in a 500 Internal Server Error
    # if not explicitly caught), mimicking the behavior of the original `eval()` call.
    result = safe_eval_math_expression(expression)

    return jsonify({
        "expression": expression,
        "result": result
    })


if __name__ == "__main__":
    app.run(debug=True)
