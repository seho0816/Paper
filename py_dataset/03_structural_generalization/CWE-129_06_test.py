from dataclasses import dataclass


@dataclass(frozen=True)
class MenuSelection:
    account_id: str
    menu_index: int


class MenuService:
    def select(
        self,
        request: MenuSelection,
        available_items: list[dict],
    ) -> dict:
        selected = available_items[
            request.menu_index
        ]
        save_selection(
            request.account_id,
            selected,
        )

        return selected
