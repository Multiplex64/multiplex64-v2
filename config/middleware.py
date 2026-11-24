import logging
import time
import json

plaintext_logger = logging.getLogger("plaintext_request_logger")
json_logger = logging.getLogger("json_request_logger")


class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Start timer before processing the request
        start_time = time.monotonic()

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
            f"{request.method.ljust(8)} "
            f"{request.get_full_path()} "
            f"{duration_ms:.2f}ms "
            f"{user}"
        )

        json_logger.info(
            json.dumps(
                {
                    "request": {
                        "time": start_time,
                        "method": request.method,
                        "path": request.get_full_path(),
                        "address": client_ip,
                        "size": len(request.body),
                        "user_agent": request.headers.get("User-Agent"),
                        "referrer": request.headers.get("Referer"),
                    },
                    "response": {
                        "duration": f"{duration_ms:.2f}",
                        "code": response.status_code,
                        "size": content_length,
                    },
                }
            )
        )

        return response
