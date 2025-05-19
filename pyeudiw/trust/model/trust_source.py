from dataclasses import dataclass
from typing import Optional, Dict, Any

from cryptojwt.jwk.jwk import key_from_jwk_dict

from pyeudiw.jwk import JWK
from pyeudiw.tools.utils import iat_now

@dataclass
class TrustEvaluationType:
    """
    TrustEvaluationType is a dataclass that holds one of the trust parameters for a trust source.
    """

    def __init__(
        self,
        attribute_name: str,
        expiration_date: int,
        jwks: list[dict[str, str]] | list[JWK] = [],
        trust_handler_name: str = "",
        **kwargs
    ) -> None:
        """
        Initialize the trust parameter data.

        :param attribute_name: The attribute name of the the field that holds the trust parameter data
        :type attribute_name: str
        :param expiration_date: The expiration date in unix timestamp of the trust parameter data
        :type expiration_date: int
        :param jwks: The jwks of the trust parameter data
        :type jwks: list[dict[str, str]] | list[JWK], optional
        :param trust_handler_name: The trust handler that handles the trust parameter data
        :type trust_handler_name: str, optional
        """

        self.attribute_name = attribute_name
        self.expiration_date = expiration_date
        self.trust_handler_name = trust_handler_name

        self.jwks = []

        for jwk in jwks:
            jwk = key_from_jwk_dict(jwk).serialize(private=False) if isinstance(jwk, dict) else jwk.as_public_dict()
            self.jwks.append(jwk)

        for ttype, tp in kwargs.items():
            setattr(self, ttype, tp)

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize the trust parameter data.

        :returns: The serialized trust parameter data
        :rtype: dict[str, any]
        """
        return {
            "attribute_name": self.attribute_name,
            "expiration_date": self.expiration_date,
            "jwks": [key_from_jwk_dict(jwk).serialize(private=False) for jwk in self.jwks],
            "trust_handler_name": self.trust_handler_name,
            self.attribute_name: getattr(self, self.attribute_name)
        }

    @property
    def expired(self) -> bool:
        """
        Return whether the trust parameter data has expired.

        :returns: Whether the trust parameter data has expired
        :rtype: bool
        """
        return iat_now() > self.expiration_date
    
    def get_jwks(self) -> list[dict]:
        return self.jwks

@dataclass
class TrustSourceData:
    """
    TrustSourceData is a dataclass that holds the trust data of a trust source.
    """

    def __init__(
        self,
        entity_id: str,
        policies: dict = {},
        metadata: dict = {},
        revoked: bool = False,
        **kwargs
    ) -> None:
        """
        Initialize the trust source data.

        :param entity_id: The entity id of the trust source
        :type entity_id: str
        :param policies: The policies of the trust source
        :type policies: dict, optional
        :param metadata: The metadata of the trust source
        :type metadata: dict, optional
        :param revoked: Whether the trust source is revoked
        :type revoked: bool, optional
        """
        self.entity_id = entity_id
        self.policies = policies
        self.revoked = revoked

        if "jwks" in metadata and "keys" in metadata["jwks"]:
            metadata["jwks"]["keys"] = [key_from_jwk_dict(jwk).serialize(private=False) for jwk in metadata["jwks"]["keys"]]

        self.metadata = metadata
        for _type, tp in kwargs.items():
            setattr(self, _type, TrustEvaluationType(**tp)) 

    
    def add_trust_param(self, ttype: str, trust_params: TrustEvaluationType) -> None:
        """
        Add a trust source to the trust source.

        :param type: The type of the trust source
        :type type: str
        :param trust_params: The trust parameters of the trust source
        :type trust_params: TrustEvaluationType
        """
        setattr(self, ttype, trust_params)

    def has_trust_param(self, ttype: str) -> bool:
        """
        Return whether the trust source has a trust source of the given type.

        :param type: The type of the trust source
        :type type: str
        :returns: Whether the trust source has a trust source of the given type
        :rtype: bool
        """
        return hasattr(self, ttype)

    def get_trust_param(self, ttype: str) -> Optional[TrustEvaluationType]:
        """
        Return the trust source of the given type.

        :param type: The type of the trust source
        :type type: str
        :returns: The trust source of the given type
        :rtype: TrustEvaluationType
        """
        if not self.has_trust_param(ttype):
            return None
        return getattr(self, ttype)
    
    def get_trust_evaluation_type_by_handler_name(self, handler_name: str) -> Optional[TrustEvaluationType]:
        """
        Return the trust source of the given handler name.

        :param handler_name: The handler name of the trust source
        :type handler_name: str
        :returns: The trust source of the given handler name
        :rtype: TrustEvaluationType
        """
        for ttype in dir(self):
            if isinstance(getattr(self, ttype), TrustEvaluationType):
                if getattr(self, ttype).trust_handler_name == handler_name:
                    return getattr(self, ttype)
        return None

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize the trust source data.

        :returns: The serialized trust source data
        :rtype: dict[str, any]
        """

        trust_source = {
            "entity_id": self.entity_id,
            "policies": self.policies,
            "revoked": self.revoked,
        }

        tmp_metadata = self.metadata.copy()

        if "jwks" in tmp_metadata and "keys" in tmp_metadata["jwks"]:
            tmp_metadata["jwks"]["keys"] = [key_from_jwk_dict(jwk).serialize(private=False) for jwk in tmp_metadata["jwks"]["keys"]]

        trust_source["metadata"] = tmp_metadata

        for ttype in dir(self):
            if isinstance(getattr(self, ttype), TrustEvaluationType):
                trust_source[ttype] = getattr(self, ttype).serialize()

        return trust_source
    
    def is_revoked(self) -> bool:
        """
        Return whether the trust source is revoked.

        :returns: Whether the trust source is revoked
        :rtype: bool
        """
        return self.revoked

    @staticmethod
    def empty(entity_id: str) -> "TrustSourceData":
        """
        Return the empty trust source data.

        :param entity_id: The entity id of the trust source
        :type entity_id: str
        :returns: The empty trust source data
        :rtype: TrustSourceData
        """
        return TrustSourceData(
            entity_id, 
            policies={}, 
            metadata={}, 
            revoked=False
        )

    @staticmethod
    def from_dict(data: dict) -> "TrustSourceData":
        """
        Return the trust source data from the given dictionary.

        :param data: The dictionary to create the trust source data from
        :type data: dict
        :returns: The trust source data from the given dictionary
        :rtype: TrustSourceData
        """
        return TrustSourceData(**data)
