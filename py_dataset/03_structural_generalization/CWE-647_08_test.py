from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class RouteRequest:
    raw_target: str
    current_user: dict


class RouteDispatcher:
    def execute(
        self,
        request: RouteRequest,
    ):
        if (
            request.raw_target.startswith(
                '/management'
            )
            and request.current_user.get(
                'role'
            ) != 'manager'
        ):
            raise PermissionError(
                'access denied'
            )

        decoded = unquote(
            request.raw_target
        )
        canonical_segments = [
            segment
            for segment in decoded.split('/')
            if segment not in {
                '',
                '.',
            }
        ]
        canonical_path = (
            '/'
            + '/'.join(
                canonical_segments
            )
        )

        return route_table.dispatch(
            canonical_path,
            request.current_user,
        )
