import json
import logging

from cryptojwt.jwk.jwk import key_from_jwk_dict
from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.satosa.exceptions import InvalidRequestException
from pyeudiw.satosa.frontends.openid4vci.tools.exceptions import MissingProofJWTException
from pyeudiw.satosa.frontends.openid4vci.endpoints.base_credential_endpoint import BaseCredentialEndpoint
from pyeudiw.satosa.frontends.openid4vci.models.credential_endpoint_request import CredentialEndpointRequest, ProofJWT
from pyeudiw.satosa.frontends.openid4vci.models.credential_endpoint_response import CredentialEndpointResponse
from pyeudiw.satosa.frontends.openid4vci.models.deferred_credential_endpoint_response import CredentialItem
from pyeudiw.satosa.frontends.openid4vci.models.openid4vci_basemodel import (
    OpenId4VciBaseModel,
    AUTHORIZATION_DETAILS_CTX,
    CLIENT_ID_CTX,
    ENTITY_ID_CTX,
    NONCE_CTX,
    PROOF_JWT_REQUIRED_CTX,
)
from pyeudiw.satosa.frontends.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.trust.exceptions import NoCriptographicMaterial

logger = logging.getLogger(__name__)


def _jwk_thumbprint(jwk_dict: dict) -> str:
    return key_from_jwk_dict(jwk_dict).thumbprint("SHA-256")


def _verify_key_attestation(proof_jwt: str, proof_payload: dict, trust_evaluator) -> None:
    """Verify key_attestation (WUA) in proof JWT header when present."""
    try:
        header = decode_jwt_header(proof_jwt)
    except Exception:
        return
    wua_jwt = header.get("key_attestation")
    if not wua_jwt:
        return
    try:
        wua_payload_unverified = decode_jwt_payload(wua_jwt)
        wua_iss = wua_payload_unverified.get("iss")
    except Exception:
        raise InvalidRequestException("invalid key_attestation in credential proof")
    if not wua_iss:
        raise InvalidRequestException("key_attestation missing iss")
    try:
        wp_keys = trust_evaluator.get_public_keys(wua_iss)
    except NoCriptographicMaterial:
        raise InvalidRequestException("cannot resolve Wallet Provider keys for key_attestation")
    wua_helper = JWSHelper(wp_keys)
    try:
        wua_payload = wua_helper.verify(wua_jwt)
    except JWSVerificationError:
        raise InvalidRequestException("invalid key_attestation signature")
    cnf = wua_payload.get("cnf") or {}
    wua_jwk = cnf.get("jwk")
    if not wua_jwk:
        raise InvalidRequestException("key_attestation missing cnf.jwk")
    proof_jwk_str = proof_payload.get("jwk")
    if not proof_jwk_str:
        raise InvalidRequestException("proof missing jwk")
    try:
        proof_jwk = json.loads(proof_jwk_str) if isinstance(proof_jwk_str, str) else proof_jwk_str
    except (json.JSONDecodeError, TypeError):
        raise InvalidRequestException("invalid proof.jwk")
    if _jwk_thumbprint(proof_jwk) != _jwk_thumbprint(wua_jwk):
        raise InvalidRequestException("proof jwk does not match key_attestation cnf.jwk")


class CredentialHandler(BaseCredentialEndpoint):
    """
    Handle a POST request to the credential endpoint.
    """

    def validate_request(self, context: Context, entity: dict) -> OpenId4VciBaseModel:
        """
        Validate a POST request to the credential endpoint.

        This method checks whether the body of the incoming HTTP request
        contains a valid JSON structure that conforms to the
        CredentialEndpointRequest model.

        Args:
            context (Context): The SATOSA context containing request data.
            entity (dict): The stored session/entity related to the request.

        Raises:
            pydantic.ValidationError: If the request body does not match the expected schema.
        """

        body = self._get_body(context)
        if body is None:
            body_dict = {}
        elif isinstance(body, dict):
            body_dict = body
        else:
            try:
                body_dict = json.loads(body) if isinstance(body, str) else {}
            except (json.JSONDecodeError, TypeError):
                body_dict = {}
        proof = body_dict.get("proof")
        proof_jwt = None
        if isinstance(proof, dict):
            proof_jwt = proof.get("jwt") or ""
        proof_jwt = (proof_jwt or "").strip() if proof_jwt else None

        if self.proof_jwt_required and not proof_jwt:
            raise MissingProofJWTException("missing proof JWT")
        if not self.proof_jwt_required and not proof_jwt:
            logger.debug("Missing JWTProof since it is not configured")

        c_req = CredentialEndpointRequest.model_validate(
            body_dict,
            context={
                AUTHORIZATION_DETAILS_CTX: entity.get("authorization_details", {}),
                PROOF_JWT_REQUIRED_CTX: self.proof_jwt_required,
            },
        )

        if not c_req.proof or not c_req.proof.jwt:
            return c_req

        proof_jws_helper = JWSHelper(self.config["metadata_jwks"])
        proof_payload = proof_jws_helper.verify(c_req.proof.jwt)
        _verify_key_attestation(c_req.proof.jwt, proof_payload, self._trust_evaluator)
        ProofJWT.model_validate(
            proof_payload, context={CLIENT_ID_CTX: entity["client_id"], ENTITY_ID_CTX: self.entity_id, NONCE_CTX: entity["c_nonce"]}
        )
        return c_req

    def to_response(self, context: Context, entity: OpenId4VCIEntity, credential_id: str | None) -> Response:
        """
        Generate a response containing the issued credential.

        This method handles the issuance of the requested credential (e.g., SD-JWT)
        and formats it into a compliant response using the
        CredentialEndpointResponse helper.

        Args:
            context (Context): The SATOSA context.
            entity (OpenId4VCIEntity): The entity containing stateful session data.

        Returns:
            Response: A SATOSA HTTP response with the issued credential.
        """

        return CredentialEndpointResponse.to_response([CredentialItem(credential=cred) for cred in self.build_credential(context, credential_id)])
