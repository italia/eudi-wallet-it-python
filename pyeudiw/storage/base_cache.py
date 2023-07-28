from typing import Callable


class BaseCache():
    def try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> dict:
        raise NotImplementedError()

    def overwrite(self, object_name: str, value_gen_fn: Callable[[], str]) -> dict:
        raise NotImplementedError()
