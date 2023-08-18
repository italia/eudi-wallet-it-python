class ChainAlreadyExist(BaseException):
    pass


class ChainNotExist(BaseException):
    pass


class StorageWriteError(BaseException):
    pass


class StorageEntryUpdateFailed(BaseException):
    pass


class EntryNotFound(BaseException):
    pass
