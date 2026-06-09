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
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"{type(error).__name__}: {error}",
            )
