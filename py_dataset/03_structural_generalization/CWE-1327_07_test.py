from dataclasses import dataclass


@dataclass(frozen=True)
class MetricsConfiguration:
    bind_address: str = '0.0.0.0'
    port: int = 9600


class MetricsServer:
    def __init__(
        self,
        configuration: MetricsConfiguration,
    ) -> None:
        self._configuration = configuration

    def start(
        self,
    ) -> None:
        metrics_application.run(
            host=self._configuration.bind_address,
            port=self._configuration.port,
        )
