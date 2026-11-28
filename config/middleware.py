import datetime
import hashlib
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
            client_ip = x_forwarded_for.split(",")[-1].strip()
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

        # Get the view name
        resolver = getattr(request, "resolver_match", None)
        view_name = getattr(resolver, "view_name", None) if resolver else None

        # Identify authenticated user if available
        user_name = (
            request.user.username
            if hasattr(request, "user") and request.user.is_authenticated
            else "Anonymous"
        )

        # Get user ID
        user = getattr(request, "user", None)
        user_id = user.id if user and user.is_authenticated else None

        # Get session
        session = getattr(request, "session", None)
        session_key = session.session_key if session else None

        # Hash session id
        hashed_session_id = (
            hashlib.sha256(session_key.encode()).hexdigest() if session_key else None
        )

        # Get response size
        if response.streaming:
            response_size = -1
        else:
            response_size = len(response.content)

        # Calculate total processing duration in milliseconds
        duration_us = round((time.monotonic() - start_time) * 1000000)

        # Log the details
        plaintext_logger.info(
            f"{client_ip.ljust(15)} "
            f"{response.status_code} "
            f"{request.method[:3]} "
            f"{request.get_full_path()} - "
            f"{user_name} "
            f"{duration_us}us"
        )

        # JSON log of all HTTP requests
        json_logger.info(
            json.dumps(
                {
                    "timestamp": utc_time,
                    "trace_id": request.id,
                    "view": view_name,
                    # "level": "info", # Not used, all logs in this file are info level
                    # "env": "prod", # Not used, each env already has separate logs
                    "request": {
                        "method": request.method,
                        # "host": request.get_host(), # Not used, serves one domain
                        "path": request.get_full_path(),
                        "ip": client_ip, # Uses X-Forwarded-For
                        "size": request_size,
                        "user_id": user_id,
                        "session_id": hashed_session_id,
                        "referer": request.headers.get("Referer"),
                        "user_agent": request.headers.get("User-Agent"),
                    },
                    "response": {
                        "status_code": response.status_code,
                        "size": response_size, # Defaults to -1 when it is a streaming response
                        "duration_us": duration_us,
                    },
                }
            )
        )

        return response
