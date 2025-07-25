import datetime

def is_valid_unix_timestamp(ts: int, range=60) -> bool:
  """
  Checks if the given value is a valid UNIX timestamp (in seconds).

  Args:
      ts (int): Timestamp to validate.

  Returns:
      bool: True if valid UNIX timestamp, False otherwise.
  """
  if not ts or ts == 0:
    return False
  if not isinstance(ts, int):
    return False
  try:
    # Check if datetime.fromtimestamp works and the value is in a reasonable range
    datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    if not range:
      return True
    # Accept timestamps in a reasonable window, +/- given seconds (default 60)  from now
    now = datetime.datetime.now(datetime.timezone.utc)
    earliest = now.timestamp() - range
    latest = now.timestamp() + range
    return earliest <= ts <= latest
  except (OverflowError, OSError, ValueError):
    return False