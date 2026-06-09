import os
import grpc

class MaintenanceService:
    def RebuildIndex(
        self,
        request,
        context,
    ):
        # CWE-425: Direct Request ('Forced Browsing')
        # The original code directly uses 'request.index_name' without verifying
        # if the user is authorized to perform operations on that specific index.
        # This allows an attacker to potentially access or modify indices they
        # should not have access to (e.g., sensitive production indices).
        #
        # To fix this, we introduce an authorization check to ensure that the
        # requested 'index_name' is within a list of allowed indices for the
        # current operation/context. The list of authorized indices is configured
        # via an environment variable for flexibility and to avoid hardcoding.

        # Retrieve a comma-separated string of authorized index names from an
        # environment variable. A default list is provided if the environment
        # variable is not set.
        authorized_indices_str = os.environ.get("ALLOWED_REBUILD_INDICES", "prod_main_index,test_index")
        
        # Parse the string into a set for efficient lookup.
        authorized_indices = {name.strip() for name in authorized_indices_str.split(',') if name.strip()}

        # Check if the requested index name is in the set of authorized indices.
        if request.index_name not in authorized_indices:
            # If the index is not authorized, abort the operation with a
            # PERMISSION_DENIED status, consistent with gRPC error handling.
            context.abort(grpc.StatusCode.PERMISSION_DENIED, f"Unauthorized to rebuild index: {request.index_name}")

        # If the index name is authorized, proceed with the original functionality
        # of rebuilding the search index.
        rebuild_search_index(
            request.index_name
        )

        return {
            "completed": True,
        }
