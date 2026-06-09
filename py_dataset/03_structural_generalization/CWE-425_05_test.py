from dataclasses import dataclass


@dataclass(frozen=True)
class InternalRequest:
    path: str
    user: dict


class InternalRouteDispatcher:
    def dispatch(
        self,
        request: InternalRequest,
    ) -> dict:
        if request.path == (
            "/internal/export/customers"
        ):
            return {
                "content": export_customers(),
            }

        if request.path == (
            "/internal/rebuild/search"
        ):
            rebuild_search_index()

            return {
                "rebuilt": True,
            }

        return {
            "status": "not_found",
        }
