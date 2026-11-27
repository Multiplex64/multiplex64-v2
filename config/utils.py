import logging
from datetime import datetime, timezone


# Format log time into ISO 8601
class ISO8601Formatter(logging.Formatter):
    """Class for formatting asctime into UTC time"""

    def formatTime(self, record, datefmt=None):
        # Use timezone.utc for UTC logs, or .astimezone() for local server time
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
