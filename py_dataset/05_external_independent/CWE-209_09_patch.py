import grpc


class ReportService:
    def GetReport(
        self,
        request,
        context,
    ):
        try:
            return load_report(
                request.report_id,
            )
        except Exception as error:
            # CWE-209: Generation of Error Message Containing Sensitive Information
            # Avoid exposing internal error details to the client.
            # Instead, provide a generic error message.
            # The detailed error can be logged internally for debugging if needed.
            context.abort(
                grpc.StatusCode.INTERNAL,
                "An internal error occurred while processing the request.",
            )
