class ConversionService:
    def Convert(self, request, context):
        entered = sandbox_runtime.enter(
            request.worker_profile
        )
        if not entered:
            context.set_trailing_metadata((
                ("sandbox-warning", "not-applied"),
            ))

        return convert_payload(
            request.payload
        )
