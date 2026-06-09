from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosticRoute:
    path: str
    handler: object


class DiagnosticRouter:
    def routes(
        self,
    ) -> list[DiagnosticRoute]:
        return [
            DiagnosticRoute(
                path='/debug/configuration',
                handler=export_configuration,
            ),
            DiagnosticRoute(
                path='/debug/cache',
                handler=export_cache_state,
            ),
            DiagnosticRoute(
                path='/debug/database',
                handler=export_database_metadata,
            ),
        ]
