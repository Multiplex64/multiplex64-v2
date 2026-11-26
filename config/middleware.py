import logging
import time
import json
import uuid
import datetime

plaintext_logger = logging.getLogger("plaintext_request_logger")
json_logger = logging.getLogger("json_request_logger")


class RequestUUIDMiddleware:
    """Middleware to generate a UUID for each request"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid7())

        request.id = request_id

        response = self.get_response(request)

        # Return the UUID in the response headers
        response["X-Request-ID"] = request_id
        return response


class RequestLoggingMiddleware:
    """Log all HTTP requests to both human readable .log file and machine readable .jsonl file"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Start timer before processing the request
        start_time = time.monotonic()
        utc_time = time.time()
        date_time = datetime.datetime.now()

        # 2. Extract client IP (handles reverse proxies like Nginx)
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.META.get("REMOTE_ADDR")

        # 3. Pass request down to the view and capture the response
        response = self.get_response(request)

        # 4. Calculate total processing duration in milliseconds
        duration_ms = (time.monotonic() - start_time) * 1000

        # 5. Identify authenticated user if available
        user = (
            request.user.username
            if hasattr(request, "user") and request.user.is_authenticated
            else "Anonymous"
        )
        if response.streaming:
            # Handle streaming responses (e.g., use streaming_content or skip length check)
            content_length = -1
        else:
            content_length = len(response.content)

        # 6. Log the structured details
        plaintext_logger.info(
            f"{client_ip.ljust(15)} "
            f"{response.status_code} "
            f"{request.method[:3]} "
            f"{request.get_full_path()} - "
            f"{user} "
            f"{duration_ms:.0f}ms"
        )

        json_logger.info(
            json.dumps(
                {
                    "time": date_time.isoformat() + "Z",
                    "id": request.id,
                    "request": {
                        "method": request.method,
                        # "host": request.get_host(), # Not used, serves one domain
                        "path": request.get_full_path(),
                        "ip": client_ip,
                        "size": len(request.body),
                        "user_id": (
                            request.user.id if hasattr(request, "user") else None
                        ),
                        "referer": request.headers.get("Referer"),
                        "user_agent": request.headers.get("User-Agent"),
                    },
                    "response": {
                        "code": response.status_code,
                        "size": content_length,
                        "duration_ms": round(duration_ms, 2),
                        "view_name": getattr(request.resolver_match, "view_name", None),
                    },
                }
            )
        )

        return response
