import random
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceEnrollmentRequest:
    account_id: int
    device_label: str


class DeviceSecretGenerator:
    def __init__(self) -> None:
        self._generator = random.Random()

    def create_bootstrap_secret(self) -> str:
        secret_value = self._generator.getrandbits(192)
        return f"{secret_value:048x}"


class EnrollmentRepository:
    def __init__(self) -> None:
        self._records: dict[int, dict[str, str]] = {}

    def save(
        self,
        request: DeviceEnrollmentRequest,
        bootstrap_secret: str,
    ) -> None:
        self._records[request.account_id] = {
            "device_label": request.device_label,
            "bootstrap_secret": bootstrap_secret,
        }


class DeviceEnrollmentService:
    def __init__(
        self,
        generator: DeviceSecretGenerator,
        repository: EnrollmentRepository,
    ) -> None:
        self._generator = generator
        self._repository = repository

    def enroll(self, payload: dict) -> dict:
        request = DeviceEnrollmentRequest(
            account_id=int(payload["account_id"]),
            device_label=str(payload["device_label"]),
        )
        bootstrap_secret = self._generator.create_bootstrap_secret()
        self._repository.save(request, bootstrap_secret)

        return {
            "account_id": request.account_id,
            "bootstrap_secret": bootstrap_secret,
        }


repository = EnrollmentRepository()
service = DeviceEnrollmentService(
    DeviceSecretGenerator(),
    repository,
)


def enroll_device(payload: dict) -> dict:
    return service.enroll(payload)
