import pymongo
from datetime import datetime
from typing import Callable

from .base_cache import BaseCache


class MongoCache(BaseCache):
    def __init__(self, storage_conf: dict, url: str, connection_params: dict = None) -> None:
        super().__init__()

        self.storage_conf = storage_conf
        self.url = url
        self.connection_params = connection_params

        self.client = None
        self.db = None

    def _connect(self):
        if not self.client or not self.client.server_info():
            self.client = pymongo.MongoClient(
                self.url, **self.connection_params)
            self.db = getattr(self.client, self.storage_conf["db_name"])
            self.collection = getattr(self.db, "cache_storage")

    def try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> dict:
        self._connect()

        query = {"object_name": object_name}

        cache_object = self.collection.find_one(query)

        if cache_object is None:
            creation_date = datetime.timestamp(datetime.now())
            cache_object = {
                "object_name": object_name,
                "data": on_not_found(),
                "creation_date": creation_date
            }

            self.collection.insert_one(cache_object)

        return cache_object

    def overwrite(self, object_name: str, value_gen_fn: Callable[[], str]) -> dict:
        self._connect()

        new_data = value_gen_fn()
        updated_date = datetime.timestamp(datetime.now())

        cache_object = {
            "object_name": object_name,
            "data": new_data,
            "creation_date": updated_date
        }

        query = {"object_name": object_name}

        self.collection.update_one(query, {
            "$set": {
                "data": new_data,
                "creation_date": updated_date
            }
        })

        return cache_object
