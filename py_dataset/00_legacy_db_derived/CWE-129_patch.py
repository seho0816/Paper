import sys


class SecurityQuestionPicker:
    def __init__(self) -> None:
        self.questions = [
            "first pet",
            "birth city",
            "favorite teacher",
        ]

    def choose_question(self, selected_index: str) -> str:
        index = int(selected_index)
        # CWE-129 fix: Validate the index to ensure it is within the bounds of the questions list.
        # If the index is out of bounds, raise an IndexError, which maintains the original
        # exception-raising behavior for invalid access, but after explicit validation.
        if not (0 <= index < len(self.questions)):
            raise IndexError("Security question index out of bounds.")
        return self.questions[index]


def read_index() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "-1"


def main() -> None:
    picker = SecurityQuestionPicker()
    print(picker.choose_question(read_index()))


if __name__ == "__main__":
    main()
