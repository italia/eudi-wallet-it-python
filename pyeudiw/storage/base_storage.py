import datetime
from enum import Enum
from typing import Union
from pymongo.results import UpdateResult

from .base_db import BaseDB


class TrustType(Enum):
    X509 = "x509"
    FEDERATION = "federation"
    DIRECT_TRUST_SD_JWT_VC = "direct_trust_sd_jwt_vc"


trust_type_map: dict = {
    TrustType.X509: "x509",
    TrustType.FEDERATION: "federation",
    TrustType.DIRECT_TRUST_SD_JWT_VC: "direct_trust_sd_jwt_vc"
}

trust_attestation_field_map: dict = {
    TrustType.X509: "x5c",
    TrustType.FEDERATION: "chain"
}

trust_anchor_field_map: dict = {
    TrustType.X509: "pem",
    TrustType.FEDERATION: "entity_configuration"
}


class BaseStorage(BaseDB):
    """
    Interface class for storage.
    """

    def init_session(self, document_id: str, dpop_proof: dict, attestation: dict) -> str:
        """
        Initialize a session.

        :param document_id: the document id.
        :type document_id: str
        :param dpop_proof: the dpop proof.
        :type dpop_proof: dict
        :param attestation: the attestation.
        """
        raise NotImplementedError()

    def set_session_retention_ttl(self, ttl: int) -> None:
        """
        Set the database retention ttl.

        :param ttl: the ttl.
        :type ttl: int | None
        """
        raise NotImplementedError()

    def has_session_retention_ttl(self) -> bool:
        """
        Check if the session has a retention ttl.

        :returns: True if the session has a retention ttl, False otherwise.
        :rtype: bool
        """
        raise NotImplementedError()

    def add_dpop_proof_and_attestation(self, document_id, dpop_proof: dict, attestation: dict) -> UpdateResult:
        """
        Add a dpop proof and an attestation to the session.

        :param document_id: the document id.
        :type document_id: str
        :param dpop_proof: the dpop proof.
        :type dpop_proof: dict
        :param attestation: the attestation.
        :type attestation: dict

        :returns: the result of the update operation.
        :rtype: UpdateResult
        """
        raise NotImplementedError()

    def set_finalized(self, document_id: str) -> UpdateResult:
        """
        Set the session as finalized.

        :param document_id: the document id.
        :type document_id: str

        :returns: the result of the update operation.
        :rtype: UpdateResult
        """

        raise NotImplementedError()

    def update_request_object(self, document_id: str, request_object: dict) -> UpdateResult:
        """
        Update the request object of the session.

        :param document_id: the document id.
        :type document_id: str
        :param request_object: the request object.
        :type request_object: dict

        :returns: the result of the update operation.
        :rtype: UpdateResult
        """
        raise NotImplementedError()

    def update_response_object(self, nonce: str, state: str, response_object: dict) -> UpdateResult:
        """
        Update the response object of the session.

        :param nonce: the nonce.
        :type nonce: str
        :param state: the state.
        :type state: str
        :param response_object: the response object.
        :type response_object: dict

        :returns: the result of the update operation.
        :rtype: UpdateResult
        """
        raise NotImplementedError()

    def get_trust_attestation(self, entity_id: str) -> Union[dict, None]:
        """
        Get a trust attestation.

        :param entity_id: the entity id.
        :type entity_id: str

        :returns: the trust attestation.
        :rtype: Union[dict, None]
        """
        raise NotImplementedError()

    def get_trust_anchor(self, entity_id: str) -> Union[dict, None]:
        """
        Get a trust anchor.

        :param entity_id: the entity id.
        :type entity_id: str

        :returns: the trust anchor.
        :rtype: Union[dict, None]
        """
        raise NotImplementedError()

    def has_trust_attestation(self, entity_id: str) -> bool:
        """
        Check if a trust attestation exists.

        :param entity_id: the entity id.
        :type entity_id: str


        :returns: True if the trust attestation exists, False otherwise.
        :rtype: bool
        """
        raise NotImplementedError()

    def has_trust_anchor(self, entity_id: str) -> bool:
        """
        Check if a trust anchor exists.

        :param entity_id: the entity id.
        :type entity_id: str

        :returns: True if the trust anchor exists, False otherwise.
        :rtype: bool
        """
        raise NotImplementedError()
    
    def has_trust_source(self, entity_id: str) -> bool:
        raise NotImplementedError()

    def add_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime, trust_type: TrustType, jwks: dict) -> str:
        """
        Add a trust attestation.

        :param entity_id: the entity id.
        :type entity_id: str
        :param attestation: the attestation.
        :type attestation: list[str]
        :param exp: the expiration date.
        :type exp: datetime
        :param trust_type: the trust type.
        :type trust_type: TrustType
        :param jwks: cached jwks
        :type jwks: dict

        :returns: the document id.
        :rtype: str
        """
        raise NotImplementedError()

    def add_trust_attestation_metadata(self, entity_id: str, metadata_type: str, metadata: dict) -> str:
        """
        Add a trust attestation metadata.

        :param entity_id: the entity id.
        :type entity_id: str
        :param metadata_type: the metadata type.
        :type metadata_type: str

        :returns: the document id.
        :rtype: str
        """
        raise NotImplementedError()
    
    def add_trust_source(self, entity_id: str, trust_source: dict) -> str:
        """
        Add a trust source.

        :param entity_id: the entity id.
        :type entity_id: str
        :param trust_source: the trust source.
        :type trust_source: dict

        :returns: the document id.
        :rtype: str
        """
        raise NotImplementedError()
    
    def get_trust_source(self, entity_id: str) -> Union[dict, None]:
        """
        Get a trust source.

        :param entity_id: the entity id.
        :type entity_id: str

        :returns: the trust source.
        :rtype: Union[dict, None]
        """
        raise NotImplementedError()

    def add_trust_anchor(self, entity_id: str, entity_configuration: str, exp: datetime, trust_type: TrustType):
        """
        Add a trust anchor.

        :param entity_id: the entity id.
        :type entity_id: str
        :param entity_configuration: the entity configuration.
        :type entity_configuration: str
        :param exp: the expiration date.
        :type exp: datetime
        :param trust_type: the trust type.
        :type trust_type: TrustType

        :returns: the document id.
        :rtype: str
        """
        raise NotImplementedError()

    def update_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime, trust_type: TrustType, jwks: dict) -> str:
        """
        Update a trust attestation.

        :param entity_id: the entity id.
        :type entity_id: str
        :param attestation: the attestation.
        :type attestation: list[str]
        :param exp: the expiration date.
        :type exp: datetime
        :param trust_type: the trust type.
        :type trust_type: TrustType
        :param jwks: cached jwks
        :type jwks: dict

        :returns: the document id.
        :rtype: str
        """
        raise NotImplementedError()

    def update_trust_anchor(self, entity_id: str, entity_configuration: str, exp: datetime, trust_type: TrustType) -> str:
        """
        Update a trust anchor.

        :param entity_id: the entity id.
        :type entity_id: str
        :param entity_configuration: the entity configuration.
        :type entity_configuration: str
        :param exp: the expiration date.
        :type exp: datetime
        :param trust_type: the trust type.
        :type trust_type: TrustType

        :returns: the document id.
        :rtype: str
        """
        raise NotImplementedError()

    def exists_by_state_and_session_id(self, state: str, session_id: str = "") -> bool:
        """
        Check if a session exists by state and session id.

        :param state: the state.
        :type state: str
        :param session_id: the session id.
        :type session_id: str

        :returns: True if the session exists, False otherwise.
        :rtype: bool
        """
        raise NotImplementedError()

    def get_by_state(self, state: str) -> Union[dict, None]:
        """
        Get a session by state.

        :param state: the state.
        :type state: str

        :returns: the session.
        :rtype: Union[dict, None]
        """
        raise NotImplementedError()

    def get_by_nonce_state(self, state: str, nonce: str) -> Union[dict, None]:
        """
        Get a session by nonce and state.

        :param state: the state.
        :type state: str
        :param nonce: the nonce.
        :type nonce: str

        :returns: the session.
        :rtype: Union[dict, None]
        """
        raise NotImplementedError()

    def get_by_state_and_session_id(self, state: str, session_id: str = "") -> Union[dict, None]:
        """
        Get a session by state and session id.

        :param state: the state.
        :type state: str
        :param session_id: the session id.
        :type session_id: str

        :returns: the session.
        :rtype: Union[dict, None]
        """
        raise NotImplementedError()

    def get_by_session_id(self, session_id: str) -> Union[dict, None]:
        """
        Get a session by session id.

        :param session_id: the session id.
        :type session_id: str

        :returns: the session.
        :rtype: Union[dict, None]
        """
        raise NotImplementedError()

    # TODO: create add_or_update for all the write methods
    def add_or_update_trust_attestation(self, entity_id: str, attestation: list[str], exp: datetime) -> str:
        """
        Add or update a trust attestation.

        :param entity_id: the entity id.
        :type entity_id: str
        :param attestation: the attestation.
        :type attestation: list[str]
        :param exp: the expiration date.
        :type exp: datetime

        :returns: the document id.
        :rtype: str
        """
        raise NotImplementedError()

    @property
    def is_connected(self) -> bool:
        """
        Check if the storage is connected.

        :returns: True if the storage is connected, False otherwise.
        :rtype: bool
        """
        raise NotImplementedError()
