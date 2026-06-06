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
