from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class TrustParameterData:
    """
    TrustParameterData is a dataclass that holds one of the trust parameters for a trust source.
    """

    def __init__(
        self,
        attribute_name: str,
        expiration_date: datetime,
        jwks: list[dict] = [],
        trust_handler_name: str = "",
        **kwargs
    ) -> None:
        """
        Initialize the trust parameter data.

        :param attribute_name: The attribute name of the the field that holds the trust parameter data
        :type attribute_name: str
        :param expiration_date: The expiration date of the trust parameter data
        :type expiration_date: datetime
        :param jwks: The jwks of the trust parameter data
        :type jwks: list[dict], optional
        :param trust_handler_name: The trust handler that handles the trust parameter data
        :type trust_handler_name: str, optional
        """

        self.attribute_name = attribute_name
        self.expiration_date = expiration_date
        self.jwks = jwks
        self.trust_handler_name = trust_handler_name

        for type, tp in kwargs.items():
            setattr(self, type, tp)

    def selfissued_jwt_header_trust_parameters(self) -> dict[str, any]:
        """
        Return the trust parameters for the self-issued jwt header.

        :returns: The trust parameters for the self-issued jwt header
        :rtype: dict[str, any]
        """
        return {self.type: getattr(self, self.attribute_name)}

    def serialize(self) -> dict[str, any]:
        """
        Serialize the trust parameter data.

        :returns: The serialized trust parameter data
        :rtype: dict[str, any]
        """
        return {
            "attribute_name": self.attribute_name,
            "expiration_date": self.expiration_date,
            "jwks": self.jwks,
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
        return datetime.now() > self.expiration_date
    
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
        self.metadata = metadata
        self.revoked = revoked

        for type, tp in kwargs.items():
            setattr(self, type, TrustParameterData(**tp)) 

    
    def add_trust_param(self, type: str, trust_params: TrustParameterData) -> None:
        """
        Add a trust source to the trust source.

        :param type: The type of the trust source
        :type type: str
        :param trust_params: The trust parameters of the trust source
        :type trust_params: TrustParameterData
        """
        setattr(self, type, trust_params)

    def has_trust_param(self, type: str) -> bool:
        """
        Return whether the trust source has a trust source of the given type.

        :param type: The type of the trust source
        :type type: str
        :returns: Whether the trust source has a trust source of the given type
        :rtype: bool
        """
        return hasattr(self, type)

    def get_trust_param(self, type: str) -> Optional[TrustParameterData]:
        """
        Return the trust source of the given type.

        :param type: The type of the trust source
        :type type: str
        :returns: The trust source of the given type
        :rtype: TrustParameterData
        """
        if not self.has_trust_param(type):
            return None
        return getattr(self, type)
    
    def get_trust_param_by_handler_name(self, handler_name: str) -> Optional[TrustParameterData]:
        """
        Return the trust source of the given handler name.

        :param handler_name: The handler name of the trust source
        :type handler_name: str
        :returns: The trust source of the given handler name
        :rtype: TrustParameterData
        """
        for type in dir(self):
            if isinstance(getattr(self, type), TrustParameterData):
                if getattr(self, type).trust_handler_name == handler_name:
                    return getattr(self, type)
        return None

    def serialize(self) -> dict[str, any]:
        """
        Serialize the trust source data.

        :returns: The serialized trust source data
        :rtype: dict[str, any]
        """

        trust_source = {
            "entity_id": self.entity_id,
            "policies": self.policies,
            "metadata": self.metadata,
            "revoked": self.revoked,
        }

        for type in dir(self):
            if isinstance(getattr(self, type), TrustParameterData):
                trust_source[type] = getattr(self, type).serialize()

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