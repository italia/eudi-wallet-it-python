from pydantic import BaseModel, Field, HttpUrl


class InitParams(BaseModel):
    url: HttpUrl
    conf: dict


class StorageConfig(BaseModel):
    module: str
    class_: str = Field(..., alias='class')
    init_params: InitParams


class MongoDbConfig(BaseModel):
    cache: StorageConfig
    storage: StorageConfig


class Storage(BaseModel):
    mongo_db: MongoDbConfig
