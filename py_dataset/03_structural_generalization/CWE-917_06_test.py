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
        compiled = self._compiler.compile(
            request.expression
        )

        return compiled.execute({
            "order_total": request.order_total,
        })
