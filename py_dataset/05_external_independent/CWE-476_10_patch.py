class DeviceService:
    def GetDevice(
        self,
        request,
        context,
    ):
        device = device_repository.find(
            request.device_id
        )

        # CWE-476: NULL Pointer Dereference
        # If 'device_repository.find' returns None (device not found),
        # attempting to access 'device.device_id' or 'device.status' would
        # raise an AttributeError.
        # This check prevents dereferencing a None object.
        if device is None:
            # Return a consistent response indicating the device was not found.
            # The exact values (e.g., None, empty string, or specific status)
            # should ideally align with the API contract.
            # Here, we return the requested device_id and an explicit "NOT_FOUND" status.
            return {
                "device_id": request.device_id,
                "status": "NOT_FOUND",
            }
        else:
            return {
                "device_id": device.device_id,
                "status": device.status,
            }
