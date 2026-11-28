import datetime
import hashlib
import hmac
import json
import logging
import time
import urllib.parse

from django.conf import settings

from .utils import uuid7

plaintext_logger = logging.getLogger("plaintext_request_logger")
json_logger = logging.getLogger("json_request_logger")

SENSITIVE_QUERY_PARAMS = {
    "secret",
}


def sanitize_query_string(query_dict) -> str:
    if not query_dict:
        return ""
    sanitized = {
        k: ["[REDACTED]"] if k.lower() in SENSITIVE_QUERY_PARAMS else v
        for k, v in query_dict.lists()
    }
    return urllib.parse.urlencode(sanitized, doseq=True)


class RequestUUIDMiddleware:
    """Middleware to generate a UUID for each request"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = str(uuid7())

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

        response = None
        exc_info = None
        try:
            response = self.get_response(request)
            return response
        except Exception as exc:
            exc_info = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            duration_us = round((time.monotonic() - start_time) * 1_000_000)
            status_code = response.status_code if response else 500

            resolver = getattr(request, "resolver_match", None)
            view_name = getattr(resolver, "view_name", None)
            route = getattr(resolver, "route", None)

            user = getattr(request, "user", None)
            if user is not None and user.is_authenticated:
                user_name = user.username
                user_id = user.id
            else:
                user_name = "Anonymous"
                user_id = None

            session = getattr(request, "session", None)
            session_key = getattr(session, "session_key", None)
            hashed_session_id = (
                hmac.new(
                    settings.SECRET_KEY.encode(),
                    session_key.encode(),
                    hashlib.sha256,
                ).hexdigest()
                if session_key
                else None
            )

            if response is None:
                response_size = 0
                response_content_type = None
            elif response.streaming:
                response_size = -1
                response_content_type = response.get("Content-Type")
            else:
                response_size = len(response.content)
                response_content_type = response.get("Content-Type")

            safe_query = sanitize_query_string(request.GET)
            full_safe_path = (
                f"{request.path}?{safe_query}" if safe_query else request.path
            )
            plaintext_logger.info(
                f"{(client_ip or "-").ljust(15)} "
                f"{status_code} "
                f"{request.method.ljust(3)} "
                f"{full_safe_path} - "
                f"{user_name} "
                f"{duration_us}us"
            )

            log_payload = {
                "timestamp": utc_time,
                "request_id": getattr(request, "id", None),
                "view": view_name,
                "route": route,
                "request": {
                    "scheme": request.scheme,
                    "method": request.method,
                    "path": request.path,
                    "query": safe_query or None,
                    "ip": client_ip,
                    "size": request_size,
                    "content_type": request.content_type or None,
                    "user_id": user_id,
                    "session_id": hashed_session_id,
                    "referer": request.headers.get("Referer"),
                    "user_agent": request.headers.get("User-Agent"),
                },
                "response": {
                    "status_code": status_code,
                    "size": response_size,
                    "content_type": response_content_type,
                    "duration_us": duration_us,
                },
            }

            if exc_info:
                log_payload["error"] = exc_info

            json_logger.info(json.dumps(log_payload, separators=(",", ":")))
