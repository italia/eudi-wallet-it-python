class ChainAlreadyExist(Exception):
    pass


class ChainNotExist(Exception):
    pass


class StorageWriteError(Exception):
    pass


class StorageEntryUpdateFailed(Exception):
    pass


class EntryNotFound(Exception):
    pass
