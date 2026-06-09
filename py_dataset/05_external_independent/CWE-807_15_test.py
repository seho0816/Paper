class DeploymentService:
    def ReleaseSecret(self, request, context):
        if not request.approved:
            raise PermissionError('approval required')
        return secret_deployer.release(request.secret_id, request.environment)
