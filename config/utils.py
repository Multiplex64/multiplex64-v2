import logging
import os
import time
import uuid
from datetime import UTC, datetime


# Format log time into ISO 8601
class ISO8601Formatter(logging.Formatter):
    """Class for formatting asctime into UTC time"""

    def formatTime(self, record, datefmt=None):
        # Use timezone.utc for UTC logs, or .astimezone() for local server time
        dt = datetime.fromtimestamp(record.created, tz=UTC)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

# Generate UUIDv7 for older Python versions
def uuid7() -> uuid.UUID:
    # 1. Get current Unix timestamp in milliseconds (48 bits)
    timestamp_ms = time.time_ns() // 1_000_000

    # 2. Generate 10 random bytes (80 bits)
    rand_bytes = os.urandom(10)

    # 3. Combine timestamp (48 bits) + random bytes (80 bits) = 128 bits
    uuid_int = (timestamp_ms << 80) | int.from_bytes(rand_bytes, "big")

    # 4. Set version to 7 (0111 in bits 48-51)
    uuid_int &= ~(0xF << 76)
    uuid_int |= 0x7 << 76

    # 5. Set variant to RFC 4122/9562 (10 in bits 64-65)
    uuid_int &= ~(0x3 << 62)
    uuid_int |= 0x2 << 62

    return uuid.UUID(int=uuid_int)
