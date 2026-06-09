class VerificationStage:
    def __init__(self, verifier, next_stage) -> None:
        self._verifier = verifier
        self._next_stage = next_stage

    def handle(self, envelope: dict) -> dict:
        try:
            self._verifier.verify(envelope['body'], envelope['signature'])
        except VerificationError as error:
            envelope['verification_error'] = str(error)
            # CWE-390 fix: If verification fails, the error condition is detected.
            # The control flow must account for this error. Instead of proceeding
            # to the next stage with unverified data, return the envelope
            # with the error, effectively halting further processing in this pipeline for this envelope.
            return envelope
        return self._next_stage.handle(envelope)
