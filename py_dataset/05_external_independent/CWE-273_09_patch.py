class ConversionService:
    def Convert(self, request, context):
        entered = sandbox_runtime.enter(
            request.worker_profile
        )
        if not entered:
            context.set_trailing_metadata((
                ("sandbox-warning", "not-applied"),
            ))
            # CWE-273 fix: Abort operation if privilege drop/sandbox entry failed.
            # Continuing with un-dropped privileges would be a security vulnerability.
            raise RuntimeError("Failed to enter sandboxed environment or drop privileges.")

        return convert_payload(
            request.payload
        )
