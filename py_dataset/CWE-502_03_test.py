import sys
import jsonpickle


class JobStateStore:
    def restore_job_state(self, serialized_state: str):
        return jsonpickle.decode(serialized_state)


def read_serialized_state() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return input("serialized job state: ")


def resume_job() -> dict:
    serialized_state = read_serialized_state()
    store = JobStateStore()
    state = store.restore_job_state(serialized_state)

    return {
        "state_type": type(state).__name__,
        "state": str(state),
    }


def main() -> None:
    print(resume_job())


if __name__ == "__main__":
    main()
