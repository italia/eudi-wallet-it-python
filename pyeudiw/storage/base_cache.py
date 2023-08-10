from enum import Enum
from typing import Callable


class RetrieveStatus(Enum):
    RETRIEVED = 0
    ADDED = 1


class BaseCache():
    def try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> tuple[dict, RetrieveStatus]:
        raise NotImplementedError()

    def overwrite(self, object_name: str, value_gen_fn: Callable[[], str]) -> dict:
        raise NotImplementedError()

    def set(self, data: dict) -> dict:
        raise NotImplementedError()
