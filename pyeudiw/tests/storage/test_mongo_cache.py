import uuid
import pytest

from pyeudiw.storage.mongo_cache import MongoCache


class TestMongoCache:
    @pytest.fixture(autouse=True)
    def create_storage_instance(self):
        self.cache = MongoCache(
            {"db_name": "eudiw"},
            "mongodb://localhost:27017/",
            {}
        )

    def test_try_retrieve(self):
        object_name = str(uuid.uuid4())
        data = str(uuid.uuid4())

        obj = self.cache.try_retrieve(object_name, lambda: data)

        assert obj
        assert obj["object_name"] == object_name
        assert obj["data"] == data
        assert obj["creation_date"]

        query = {"object_name": object_name}

        cache_object = self.cache.collection.find_one(query)

        assert obj == cache_object

    def test_overwrite(self):
        object_name = str(uuid.uuid4())
        data = str(uuid.uuid4())

        obj = self.cache.try_retrieve(object_name, lambda: data)

        data_updated = str(uuid.uuid4())

        updated_obj = self.cache.overwrite(object_name, lambda: data_updated)

        assert obj["data"] != updated_obj["data"]
        assert obj["creation_date"] != updated_obj["creation_date"]

        query = {"object_name": object_name}
        cache_object = self.cache.collection.find_one(query)

        assert cache_object["data"] == updated_obj["data"]
        assert cache_object["creation_date"] == updated_obj["creation_date"]
