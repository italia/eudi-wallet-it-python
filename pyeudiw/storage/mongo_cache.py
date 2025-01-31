from datetime import datetime
from typing import Callable

import pymongo
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.mongo_client import MongoClient

from pyeudiw.storage.base_cache import BaseCache, RetrieveStatus


class MongoCache(BaseCache):
    """
    MongoDB cache implementation.
    """

    def __init__(self, conf: dict, url: str, connection_params: dict = None) -> None:
        """
        Create a MongoCache istance.

        :param conf: the configuration of the cache.
        :type conf: dict
        :param url: the url of the MongoDB server.
        :type url: str
        :param connection_params: the connection parameters.
        :type connection_params: dict, optional
        """
        super().__init__()

        self.storage_conf = conf
        self.url = url
        self.connection_params = connection_params

        self.client: MongoClient = None
        self.db: Database = None
        self.collection: Collection = None

    def close(self) -> None:
        self._connect()
        self.client.close()

    def try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> tuple[dict, RetrieveStatus]:
        self._connect()

        query = {"object_name": object_name}

        cache_object = self.collection.find_one(query)

        if cache_object is None:
            cache_object = self._gen_cache_object(object_name, on_not_found())
            self.collection.insert_one(cache_object)
            return cache_object, RetrieveStatus.ADDED

        return cache_object, RetrieveStatus.RETRIEVED

    def overwrite(self, object_name: str, value_gen_fn: Callable[[], str]) -> dict:
        self._connect()

        update_time = datetime.now().isoformat()

        new_data = value_gen_fn()
        cache_object = {
            "object_name": object_name,
            "data": new_data,
            "creation_date": update_time
        }

        query = {"object_name": object_name}

        self.collection.update_one(query, {
            "$set": {
                "data": new_data,
                "creation_date": update_time
            }
        })

        return cache_object

    def set(self, data: dict) -> dict:
        self._connect()

        return self.collection.insert_one(data)

    def _connect(self) -> None:
        if not self.client or not self.client.server_info():
            self.client = pymongo.MongoClient(
                self.url, **self.connection_params)
            self.db = getattr(self.client, self.storage_conf["db_name"])
            self.collection = getattr(self.db, "cache_storage")

    def _gen_cache_object(self, object_name: str, data: str) -> dict:
        """
        Helper function to generate a cache object.

        :param object_name: the name of the object.
        :type object_name: str
        :param data: the data to store.
        :type data: str
        """

        return {
            "object_name": object_name,
            "data": data,
            "creation_date": datetime.now().isoformat()
        }
