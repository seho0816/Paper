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
        # CWE-129: Improper Validation of Array Index
        # Validate that request.menu_index is within the valid bounds
        # of the available_items list to prevent IndexError.
        if not (0 <= request.menu_index < len(available_items)):
            raise IndexError(
                f"Menu index {request.menu_index} is out of bounds. "
                f"Valid range for available items: 0 to {len(available_items) - 1}."
            )

        selected = available_items[
            request.menu_index
        ]
        # Assuming save_selection is defined elsewhere in the application
        # as it was not part of the provided vulnerable code snippet.
        save_selection(
            request.account_id,
            selected,
        )

        return selected
