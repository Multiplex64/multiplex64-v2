import datetime
import json
import logging
import time
import uuid

plaintext_logger = logging.getLogger("plaintext_request_logger")
json_logger = logging.getLogger("json_request_logger")


class RequestUUIDMiddleware:
    """Middleware to generate a UUID for each request"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = str(uuid.uuid7())

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
        # Start timer before processing the request
        start_time = time.monotonic()
        utc_time = (
            datetime.datetime.now()
            .astimezone(datetime.UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

        # Extract client IP (handles reverse proxies like Nginx)
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.META.get("REMOTE_ADDR")

        # Get request size
        raw_content_length = request.META.get("CONTENT_LENGTH")
        request_size = (
            int(raw_content_length)
            if raw_content_length and raw_content_length.isdigit()
            else 0
        )

        # Pass request down to the view and capture the response
        response = self.get_response(request)

        # Calculate total processing duration in milliseconds
        duration_ms = (time.monotonic() - start_time) * 1000

        # Identify authenticated user if available
        user = (
            request.user.username
            if hasattr(request, "user") and request.user.is_authenticated
            else "Anonymous"
        )

        # Get response size
        if response.streaming:
            response_size = -1
        else:
            response_size = len(response.content)

        # Log the details
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
                    "time": utc_time,
                    "trace_id": request.id,
                    "view": getattr(request.resolver_match, "view_name", None),
                    "request": {
                        "method": request.method,
                        # "host": request.get_host(), # Not used, serves one domain
                        "path": request.get_full_path(),
                        "ip": client_ip,
                        "size": request_size,
                        "user_id": (
                            request.user.id if request.user.is_authenticated else None
                        ),
                        "session_id": (
                            request.session.session_key
                        ),
                        "referer": request.headers.get("Referer"),
                        "user_agent": request.headers.get("User-Agent"),
                    },
                    "response": {
                        "code": response.status_code,
                        "size": response_size,
                        "duration_ms": round(duration_ms, 2),
                    },
                }
            )
        )

        return response
