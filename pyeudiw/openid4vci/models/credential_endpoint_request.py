import logging
from typing import cast

from pydantic import model_validator

from pyeudiw.openid4vci.models.auhtorization_detail import (
    OPEN_ID_CREDENTIAL_TYPE,
    AuthorizationDetail
)
from pyeudiw.openid4vci.models.openid4vci_basemodel import (
    OpenId4VciBaseModel,
    AUTHORIZATION_DETAILS_CTX,
    CLIENT_ID_CTX,
    ENTITY_ID_CTX,
    NONCE_CTX
)
from pyeudiw.tools.date import is_valid_unix_timestamp

logger = logging.getLogger(__name__)

CREDENTIAL_ENDPOINT = "credential"
JWT_PROOF_TYPE = "jwt"
JWT_PROOF_TYP = "openid4vci-proof+jwt"

class ProofJWT(OpenId4VciBaseModel):
    """
    Represents the decoded JWT used in proof of possession.

    Attributes:
        alg (str): JWT signing algorithm used.
        typ (str): JWT type, MUST be "openid4vci-proof+jwt".
        jwk (str): The public key in JWK format.
        iss (str): JWT issuer, MUST match the client_id.
        aud (str): Audience, MUST match the entity_id of the Credential Issuer.
        iat (int): Issued At, a valid UNIX timestamp.
        nonce (str): One-time nonce for replay protection.

    Validation:
        - Each field must be non-empty (where required).
        - JWT `typ` must be "openid4vci-proof+jwt".
        - JWT `iss`, `aud`, and `nonce` must match contextual values.
    """
    alg: str = None
    typ: str = None
    jwk: str = None
    iss: str = None
    aud: str = None
    iat: int = None
    nonce: str = None

    @model_validator(mode='after')
    def check_proof(self) -> "ProofJWT":
        self.validate_alg()
        self.validate_typ()
        self.validate_jwk()
        self.validate_iss()
        self.validate_aud()
        self.validate_iat()
        self.validate_nonce()
        return self

    def validate_alg(self):
        self.alg = self.strip(self.alg)
        self.check_missing_parameter(self.alg, "proof.jwt.alg", CREDENTIAL_ENDPOINT)

    def validate_typ(self):
        self.typ = self.strip(self.typ)
        self.check_missing_parameter(self.typ, "proof.jwt.typ", CREDENTIAL_ENDPOINT)
        self.check_invalid_parameter(
            self.typ != JWT_PROOF_TYP,
            self.typ, "proof.jwt.typ", CREDENTIAL_ENDPOINT
        )

    def validate_jwk(self):
        pass

    def validate_iss(self):
        self.iss = self.strip(self.iss)
        self.check_missing_parameter(self.iss, "proof.jwt.iss", CREDENTIAL_ENDPOINT)
        self.check_invalid_parameter(
            self.iss != self.get_ctx(CLIENT_ID_CTX),
            self.iss, "proof.jwt.iss", CREDENTIAL_ENDPOINT
        )

    def validate_aud(self):
        self.aud = self.strip(self.aud)
        self.check_missing_parameter(self.aud, "proof.jwt.aud", CREDENTIAL_ENDPOINT)
        self.check_invalid_parameter(
            self.aud != self.get_ctx(ENTITY_ID_CTX),
            self.aud, "proof.jwt.aud", CREDENTIAL_ENDPOINT
        )

    def validate_iat(self):
        self.check_invalid_parameter(
            not is_valid_unix_timestamp(self.iat),
            self.iat, "proof.jwt.iat", CREDENTIAL_ENDPOINT
        )

    def validate_nonce(self):
        self.nonce = self.strip(self.nonce)
        self.check_missing_parameter(self.nonce, "proof.jwt.nonce", CREDENTIAL_ENDPOINT)
        self.check_invalid_parameter(
            self.nonce != self.get_ctx(NONCE_CTX),
            self.nonce, "proof.jwt.nonce", CREDENTIAL_ENDPOINT
        )

class Proof(OpenId4VciBaseModel):
    """
    Represents the 'proof' object required in the Credential Endpoint request, used to
    verify possession of key material by the Credential holder.

    Attributes:
        proof_type (str): MUST be "jwt". Denotes the type of the proof.
        jwt (str): A JWT string that contains the actual proof of possession.

    Validation:
        - proof_type must be present and must equal "jwt".
        - jwt must be a non-empty string.
    """
    proof_type: str = None
    jwt: str = None

    @model_validator(mode='after')
    def check_proof(self) -> "Proof":
        self.validate_prof_type()
        self.validate_jwt()
        return self

    def validate_prof_type(self):
        self.proof_type = self.strip(self.proof_type)
        self.check_missing_parameter(self.proof_type, "proof.proof_type", CREDENTIAL_ENDPOINT)
        self.check_invalid_parameter(
            JWT_PROOF_TYPE != self.proof_type,
            self.proof_type, "proof.proof_type", CREDENTIAL_ENDPOINT)

    def validate_jwt(self):
        self.jwt = self.strip(self.jwt)
        self.check_missing_parameter(self.jwt, "proof.jwt", CREDENTIAL_ENDPOINT)

class CredentialEndpointRequest(OpenId4VciBaseModel):
    """
    Model for incoming Credential Endpoint requests.

    Attributes:
        credential_identifier (str): Required if authorization_details include openid_credential.
        credential_configuration_id (str): Required only if credential_identifiers is not present.
        proof (Proof): Required. Contains the JWT-based proof.
        transaction_id (str): Optional. Required only in deferred flows.

    Validation:
        - credential_identifier must be present if openid_credential is in use.
        - credential_configuration_id must not be used when credential_identifier is present.
        - proof must include a valid JWT.
    """

    credential_identifier: str = None
    credential_configuration_id: str = None
    proof: Proof = None
    transaction_id: str = None

    @model_validator(mode='after')
    def check_credential_endpoint_request(self) -> "CredentialEndpointRequest":
        self.validate_credential_id()
        self.validate_proof()
        self.validate_transaction_id()
        return self

    def validate_credential_id(self):
        auth_det_req = cast(list[AuthorizationDetail], self.get_ctx(AUTHORIZATION_DETAILS_CTX))
        self.credential_identifier = self.strip(self.credential_identifier)
        self.credential_configuration_id = self.strip(self.credential_configuration_id)

        has_openid_credential = any(
            ad.credential_configuration_id == OPEN_ID_CREDENTIAL_TYPE
            for ad in auth_det_req
        )

        if has_openid_credential:
            self.check_missing_parameter(self.credential_identifier, "credential_identifier", CREDENTIAL_ENDPOINT)
            self.check_unexpected_parameter(self.credential_configuration_id, "credential_configuration_id", CREDENTIAL_ENDPOINT)
            valid_identifiers = []
            for ad in auth_det_req:
                if ad.credential_configuration_id == OPEN_ID_CREDENTIAL_TYPE:
                    valid_identifiers.extend(ad.credential_identifiers)
            self.check_invalid_parameter(
                self.credential_identifier not in valid_identifiers,
                self.credential_identifier, "credential_identifier", CREDENTIAL_ENDPOINT)
        else:
            self.check_missing_parameter(self.credential_configuration_id, "credential_configuration_id", CREDENTIAL_ENDPOINT)
            self.check_unexpected_parameter(self.credential_identifier, "credential_identifier", CREDENTIAL_ENDPOINT)

    def validate_proof(self):
        self.check_missing_parameter(self.proof, "proof", CREDENTIAL_ENDPOINT)
        Proof.model_validate(self.proof)

    def validate_transaction_id(self):
        pass

