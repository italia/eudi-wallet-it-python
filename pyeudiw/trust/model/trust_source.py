from dataclasses import dataclass
from pyeudiw.jwk import JWK
from datetime import datetime

@dataclass
class TrustParameterData:
    def __init__(self, type: str, trust_params: dict, expiration_date: datetime) -> None:
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
            client_id: str,
            policies: dict = {},
            metadata: dict = {},
            revoked: bool = False,
            keys: list[dict] = [],
            trust_params: dict[str, dict[str, any]] = {}
        ) -> None:
        self.client_id = client_id
        self.policies = policies
        self.metadata = metadata
        self.revoked = revoked
        self.keys = keys

        self.trust_params = [TrustParameterData(**tp) for tp in trust_params]

    @property
    def metadata(self) -> dict:
        return self.metadata

    @property
    def is_revoked(self) -> bool:
        return self.revoked

    @property
    def policies(self) -> dict:
        return self.policies
    
    @property
    def public_keys(self) -> list[dict]:
        return [JWK(k).as_public_dict() for k in self.keys]
    
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
            "client_id": self.client_id,
            "policies": self.policies,
            "metadata": self.metadata,
            "revoked": self.revoked,
            "keys": self.keys,
            "trust_params": [param.serialize() for param in self.trust_params]
        }
    
    @staticmethod
    def empty(client_id: str) -> 'TrustSourceData':
        return TrustSourceData(client_id)
    
    @staticmethod
    def from_dict(data: dict) -> 'TrustSourceData':
        return TrustSourceData(**data)
