from dataclasses import dataclass
import os

@dataclass(frozen=True)
class DiagnosticRoute:
    path: str
    handler: object

class DiagnosticRouter:
    def routes(
        self,
    ) -> list[DiagnosticRoute]:
        # CWE-489: 프로덕션 환경에서는 디버그 라우트를 노출하지 않음
        if os.environ.get("ENVIRONMENT") != "development":
            return []

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