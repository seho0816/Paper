import sys


def fetch_job_status(job_id: str) -> dict[str, str]:
    return {
        "job_id": job_id,
        "state": "running",
    }


class BatchJobWaiter:
    def wait_for_success(self, job_id: str) -> dict[str, str]:
        while True:
            status = fetch_job_status(job_id)

            if status["state"] == "succeeded":
                return status


def read_job_id() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "JOB-100"


def main() -> None:
    waiter = BatchJobWaiter()
    print(waiter.wait_for_success(read_job_id()))


if __name__ == "__main__":
    main()
