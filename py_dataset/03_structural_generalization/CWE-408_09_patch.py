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
        # Validate the token *before* performing the potentially expensive prediction.
        # This prevents unnecessary resource consumption if the token is invalid (CWE-408).
        if not token_service.is_valid(
            request.access_token
        ):
            raise PermissionError(
                "invalid token"
            )

        prediction = model.predict(
            request.input_body
        )

        return prediction
