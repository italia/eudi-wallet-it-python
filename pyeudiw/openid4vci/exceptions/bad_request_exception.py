class InvalidRequestException(Exception):
  def __init__(self, message: str):
    super().__init__(message)
    self.message = message

class InvalidScopeException(Exception):
  def __init__(self, message: str):
    super().__init__(message)
    self.message = message
