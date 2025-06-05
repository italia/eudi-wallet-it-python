from pydantic import BaseModel, Field, MongoDsn


class InitParams(BaseModel):
    url: MongoDsn
    conf: dict


class StorageConfig(BaseModel):
    module: str
    class_: str = Field(..., alias="class")
    init_params: InitParams


class MongoDbConfig(BaseModel):
    cache: StorageConfig
    storage: StorageConfig


class Storage(BaseModel):
    mongo_db: MongoDbConfig

class UserStorage(BaseModel):
    storage: StorageConfig