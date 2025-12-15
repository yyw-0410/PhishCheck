"""Common utility functions for API routers."""

from fastapi import Request


def get_client_ip(request: Request) -> str:
    """Get the real client IP address, handling proxies and load balancers.
    
    Checks headers in order of priority:
    1. CF-Connecting-IP (Cloudflare)
    2. X-Real-IP (nginx)
    3. X-Forwarded-For (standard proxy header, first IP)
    4. request.client.host (direct connection)
    
    Returns "unknown" if IP cannot be determined.
    """
    # Cloudflare
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    
    # Nginx proxy
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Standard proxy header (first IP is the original client)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # X-Forwarded-For: client, proxy1, proxy2
        return forwarded.split(",")[0].strip()
    
    # Direct connection
    if request.client and request.client.host:
        return request.client.host
    
    return "unknown"
