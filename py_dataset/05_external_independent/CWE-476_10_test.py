class DeviceService:
    def GetDevice(
        self,
        request,
        context,
    ):
        device = device_repository.find(
            request.device_id
        )

        return {
            "device_id": device.device_id,
            "status": device.status,
        }
