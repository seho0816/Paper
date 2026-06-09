from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
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
        # Assuming 'metrics_application' is an imported or globally available object
        # that has a 'run' method. If not, this part would cause a NameError.
        # As per the rules, functionality and external dependencies are kept as is.
        metrics_application.run(
            host=self._configuration.bind_address,
            port=self._configuration.port,
        )
