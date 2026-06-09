from dataclasses import dataclass


@dataclass(frozen=True)
class InferenceRequest:
    input_body: bytes
    access_token: str


class InferenceGateway:
    def predict(
        self,
        request: InferenceRequest,
    ) -> dict:
        prediction = model.predict(
            request.input_body
        )

        if not token_service.is_valid(
            request.access_token
        ):
            raise PermissionError(
                "invalid token"
            )

        return prediction
