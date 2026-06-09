from dataclasses import dataclass

from flask import Flask, jsonify, request

app = Flask(__name__)


@dataclass(frozen=True)
class CorsRequestContext:
    origin: str
    credentials_required: bool


class CorsPolicyService:
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "https://secure-frontend.example.com",
    ]

    def build_headers(
        self,
        context: CorsRequestContext,
    ) -> dict[str, str]:
        headers = {}

        if context.credentials_required and context.origin in self.ALLOWED_ORIGINS:
            headers["Access-Control-Allow-Origin"] = context.origin
            headers["Access-Control-Allow-Credentials"] = "true"

        return headers


class CustomerDataController:
    def __init__(self, policy: CorsPolicyService) -> None:
        self._policy = policy

    def create_response(self, origin: str):
        context = CorsRequestContext(
            origin=origin,
            credentials_required=True,
        )
        response = jsonify({
            "customer_id": "customer-77",
            "credit_limit": 9000000,
        })

        for name, value in self._policy.build_headers(context).items():
            response.headers[name] = value

        return response


controller = CustomerDataController(CorsPolicyService())


@app.get("/api/customer/credit")
def get_customer_credit():
    return controller.create_response(
        request.headers.get("Origin", ""),
    )
