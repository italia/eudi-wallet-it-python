from dataclasses import dataclass
from pyeudiw.jwk import JWK
from datetime import datetime

@dataclass
class TrustParameterData:
    def __init__(
            self, 
            type: str, 
            trust_params: dict, 
            expiration_date: datetime,
        ) -> None:
        self.type = type
        self.trust_params = trust_params
        self.expiration_date = expiration_date

    def selfissued_jwt_header_trust_parameters(self) -> dict:
        return {self.type: self.trust_params}
    
    def serialize(self) -> dict:
        return {
            "type": self.type,
            "trust_params": self.trust_params,
            "expiration_date": self.expiration_date
        }
    
    @property
    def expired(self) -> bool:
        return datetime.now() > self.expiration_date

@dataclass
class TrustSourceData:
    def __init__(
            self, 
            entity_id: str,
            policies: dict = {},
            metadata: dict = {},
            revoked: bool = False,
            keys: list[dict] = [],
            trust_params: dict[str, dict[str, any]] = {},
            **kwargs
        ) -> None:
        self.entity_id = entity_id
        self.policies = policies
        self.metadata = metadata
        self.revoked = revoked
        self.keys = keys

        self.additional_data = kwargs

        self.trust_params = [TrustParameterData(**tp) for tp in trust_params]
    
    def add_key(self, key: dict) -> None:
        self.keys.append(key)

    def add_keys(self, keys: list[dict]) -> None:
        self.keys.extend(keys)

    def add_trust_source(self, type: str, trust_params: TrustParameterData) -> None:
        self.trust_params[type] = trust_params
    
    def has_trust_source(self, type: str) -> bool:
        return type in self.trust_params
    
    def get_trust_source(self, type: str) -> TrustParameterData:
        return TrustParameterData(type, self.trust_params[type])
    
    def serialize(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "policies": self.policies,
            "metadata": self.metadata,
            "revoked": self.revoked,
            "keys": self.keys,
            "trust_params": [param.serialize() for param in self.trust_params]
        }
    
    @staticmethod
    def empty(entity_id: str) -> 'TrustSourceData':
        return TrustSourceData(entity_id, policies={}, metadata={}, revoked=False, keys=[], trust_params={})
    
    @staticmethod
    def from_dict(data: dict) -> 'TrustSourceData':
        return TrustSourceData(**data)
    
    @property
    def public_keys(self) -> list[dict]:
        return [JWK(k).as_public_dict() for k in self.keys]
