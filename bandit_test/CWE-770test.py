import sys

def allocate_resources(request_size):
    """VULNERABLE: Allocates memory based on user input without limits."""
    # Assume request_size comes from an HTTP request
    try:
        size = int(request_size)
        # No limit check: can lead to MemoryError or system crash
        data = [' ' * 1024 * 1024 for _ in range(size)] 
        return "Allocated successfully"
    except Exception as e:
        return str(e)

# Simulate a large user request
print(allocate_resources(100000000))