from enum import Enum
from typing import Callable


class RetrieveStatus(Enum):
    RETRIEVED = 0
    ADDED = 1


    """
    Interface class for cache storage.
    """

    def try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> tuple[dict, RetrieveStatus]:
        """
        Try to retrieve an object from the cache. If the object is not found, call the on_not_found function.

        :param object_name: the name of the object to retrieve.
        :type object_name: str
        :param on_not_found: the function to call if the object is not found.
        :type on_not_found: Callable[[], str]
        
        :returns: a tuple with the retrieved object and a status.
        :rtype: tuple[dict, RetrieveStatus]
        """
        raise NotImplementedError()

    def overwrite(self, object_name: str, value_gen_fn: Callable[[], str]) -> dict:
        """
        Overwrite an object in the cache.

        :param object_name: the name of the object to overwrite.
        :type object_name: str
        :param value_gen_fn: the function to call to generate the new value.
        :type value_gen_fn: Callable[[], str]

        :returns: the overwritten object.
        :rtype: dict
        """
        raise NotImplementedError()

    def set(self, data: dict) -> dict:
        """
        Set an object in the cache.

        :param data: the data to set.
        :type data: dict

        :returns: the setted object.
        :rtype: dict
        """
        raise NotImplementedError()
