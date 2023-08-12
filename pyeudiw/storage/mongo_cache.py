from datetime import datetime
from typing import Callable

import pymongo

from pyeudiw.storage.base_cache import BaseCache, RetrieveStatus


class MongoCache(BaseCache):
    def __init__(self, conf: dict, url: str, connection_params: dict = None) -> None:
        super().__init__()

        self.storage_conf = conf
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

    def _gen_cache_object(self, object_name: str, data: str):
        return {
            "object_name": object_name,
            "data": data,
            "creation_date": datetime.now().isoformat()
        }

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
