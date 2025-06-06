import datetime

def is_valid_unix_timestamp(ts: int) -> bool:
  """
  Checks if the given value is a valid UNIX timestamp (in seconds).

  Args:
      ts (int): Timestamp to validate.

  Returns:
      bool: True if valid UNIX timestamp, False otherwise.
  """
  if not ts:
    return False
  if not isinstance(ts, int):
    return False
  try:
    # Check if datetime.fromtimestamp works and the value is in a reasonable range
    dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    # Accept timestamps in a reasonable window, +/- 1 years from now
    earliest = now.replace(year=now.year - 1)
    latest = now.replace(year=now.year + 1)
    return earliest <= dt <= latest
  except (OverflowError, OSError, ValueError):
    return False