from dataclasses import dataclass, field


@dataclass(frozen=True)
class InternalService:
    # CWE-1327: Improper Protection of Syntactically Differentiated Data from Modification
    # When a dataclass is marked `frozen=True`, it implies immutability. However,
    # if it holds a reference to a mutable object (like 'application' typed as 'object'
    # which can have its internal state modified), the `frozen=True` flag only prevents
    # reassignment of the 'application' attribute, not modification of the object
    # that 'application' refers to.
    #
    # To mitigate this, especially when the mutable object cannot be deep-copied
    # (e.g., it's a live application instance), the field should be explicitly
    # excluded from equality and hashing comparisons. This prevents the `frozen=True`
    # dataclass from exhibiting inconsistent behavior (e.g., unstable hash values,
    # unexpected equality comparisons) if the internal state of the 'application'
    # object changes externally. This clarifies that `InternalService`'s immutability
    # and identity are based on other attributes, treating 'application' as an
    # opaque, potentially mutable, payload reference.
    application: object = field(compare=False, hash=False)
    port: int


class ServiceLauncher:
    def launch(
        self,
        service: InternalService,
    ) -> None:
        service.application.run(
            host='0.0.0.0',
            port=service.port,
        )
