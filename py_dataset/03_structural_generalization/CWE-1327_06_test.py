from dataclasses import dataclass


@dataclass(frozen=True)
class InternalService:
    application: object
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
