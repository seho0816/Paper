import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class DiscountRequest:
    expression: str
    order_total: int


class DiscountExpressionService:
    def __init__(
        self,
        compiler,
    ) -> None:
        self._compiler = compiler

    def calculate(
        self,
        request: DiscountRequest,
    ):
        try:
            tree = ast.parse(request.expression, mode='eval')
        except SyntaxError as e:
            raise ValueError(f"Invalid expression syntax: {e}") from e

        ALLOWED_NODE_TYPES = (
            ast.Expression,
            ast.Constant,
            ast.Name,
            ast.Load,
            ast.UnaryOp,
            ast.BinOp,
            ast.Compare,
            ast.BoolOp,
            ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.FloorDiv,
            ast.UAdd, ast.USub, ast.Not,
            ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
            ast.And, ast.Or,
            ast.Tuple,
        )

        for node in ast.walk(tree):
            if not isinstance(node, ALLOWED_NODE_TYPES):
                raise ValueError(f"Disallowed AST node type detected: {type(node).__name__}")

            if isinstance(node, ast.Name):
                if node.id not in ["order_total"]:
                    raise ValueError(f"Disallowed variable name detected: {node.id}")
            elif isinstance(node, ast.Constant):
                if not isinstance(node.value, (int, float, bool, type(None))):
                    raise ValueError(f"Disallowed constant value type: {type(node.value).__name__}")

        compiled = self._compiler.compile(
            request.expression
        )

        return compiled.execute({
            "order_total": request.order_total,
        })
