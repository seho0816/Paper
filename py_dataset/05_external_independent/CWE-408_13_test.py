class PredictionService:
    def Predict(
        self,
        request,
        context,
    ):
        result = model.predict(
            request.document
        )
        account = authenticate_metadata(
            context.invocation_metadata()
        )

        if account is None:
            raise PermissionError(
                "authentication required"
            )

        return {
            "result": result,
        }
