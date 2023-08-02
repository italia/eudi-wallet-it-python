from typing import Optional

from pydantic import BaseModel, create_model, HttpUrl
from typing_extensions import Annotated, Literal
from pydantic.functional_validators import AfterValidator

from pyeudiw.jwk.schema import JwkSchema
from pyeudiw.sd_jwt.schema import check_sd_jwt, check_sd_jwt_list


class DescriptorSchema(BaseModel):
    id: str
    path: str
    format: str


class PresentationSubmissionSchema(BaseModel):
    definition_id: str
    id: str
    descriptor_map: list[DescriptorSchema]


class ResponseSchema(BaseModel):
    state: Optional[str]
    vp_token: Annotated[str, AfterValidator(
        check_sd_jwt)] | Annotated[list[str], AfterValidator(check_sd_jwt_list)]
    presentation_submission: PresentationSubmissionSchema


header_model_name = "Header"
payload_model_name = "Payload"
cnf_model_name = "Cnf"
formats_supported_schema = "VpFormatsSupported"
vp_model_name = "JwtVpJson"
vc_model_name = "JwtVcJson"


class VPToken(BaseModel):
    """
    Schema to validate a VP Token. The token, in the form of a JWS header and payload,
    has the properties listed below.
        Header:
            - alg: The algorithm used to sign the JWT.
            - typ: "JWT".
            - kid: The key identifier.
        Payload:
            - vp: The digital credential in its original state.
                  `<SD-JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>`
            - jti: JWS Unique identifier.
            - iat: Unix timestamp of the issuance datetime.
            - exp: Unix timestamp beyond which the presentation of the digital credential will no longer be considered
                   valid.
            - aud: Audience of the VP, corresponding to the redirect_uri within the Authorization request issued by the
                   Relying Party.
            - nonce: Nonce provided by the Verifier within the Authorization Request.
    """
    header: create_model(header_model_name,
                         typ=(Literal["JWT"], ...),
                         alg=(Literal["ES256", "ES384", "ES512",
                              "RS256", "RS384", "RS512"], ...),
                         kid=(str, ...),
                         )

    payload: create_model(payload_model_name,
                          vp=(str, ...),
                          jti=(str, ...),
                          iat=(int, ...),
                          exp=(int, ...),
                          aud=(HttpUrl, ...),
                          nonce=(str, ...),
                          )


class WalletInstanceRequest(BaseModel):
    """
    Schema to validate a Wallet Instance Request. The request, in the form of a JWT header and payload,
    has the properties listed below.
        Header:
            - alg: Algorithm to verify the token signature
            - typ: Media type, in this case we use the value var+jwt (Verifiable Assertion Request JWT)
            - kid: Key id of the Wallet Instance
        Payload:
            - iss:
                The thumbprint
                of the JWK of the Wallet Instance
                for which the attestation is
                being requested.
            - aud:
                The public url of the Wallet Instance
                attestation issuer.
            - jti:
                Unique identifier of the request.
                This parameter will be used to
                avoid replay attacks.
            - type: String: "WalletInstanceRequest".
            - nonce:
                The nonce obtained from the
                Wallet Provider.
            - cnf:
                This parameter will contain the
                configuration of the Wallet
                Instance in JSON format. Among
                the mandatory attributes there
                will be the jwk parameter
                containing the public key of the
                Wallet Instance. It will also
                contain all the information
                useful for the Wallet Provider
                to verify that the app is genuine.
            # TODO: check why iat and exp are not in the table but found in the example
            # https://github.com/italia/eudi-wallet-it-docs/blob/versione-corrente/docs/en/wallet-instance-attestation.rst#format-of-the-wallet-instance-attestation-request
    """
    header: create_model(header_model_name,
                         alg=(Literal[
                             "RS256",
                             "RS384",
                             "RS512",
                             "ES256",
                             "ES384",
                             "ES512",
                             "PS256",
                             "PS384",
                             "PS512",
                         ], ...),
                         typ=(Literal["var+jwt"], ...),
                         kid=(str, ...))

    payload: create_model(payload_model_name,
                          iss=(str, ...),
                          aud=(HttpUrl, ...),
                          jti=(str, ...),
                          type=(
                              Literal["WalletInstanceAttestationRequest"], ...),
                          nonce=(str, ...),
                          cnf=(create_model(cnf_model_name,
                                            jwk=(JwkSchema, ...),
                                            ), ...),
                          )


class WalletInstanceAttestation(BaseModel):
    """
    Schema to validate a Wallet Instance Attestation. The attestation, in the form of a JWT header and payload,
    has the properties listed below.
        Header:
            - alg
            - typ
            - kid
            - x5c
            - trust_chain
        Payload:
            - iss: The public url of the Wallet Instance attestation issuer.
            - sub: Thumbprint value of the JWK of the Wallet Instance for which the attestation is being issued.
            - iat: Unix timestamp of the issuance datetime.
            - exp: Unix timestamp beyond which the presentation of the digital credential will no longer be considered
                   valid.
            - type: String: "WalletInstanceAttestation".
            - policy_uri: URL to the privacy policy of the wallet.
            - tos_uri: URL to the terms of use of the Wallet Provider.
            - logo_uri: URL of the Wallet Provider logo in SVG format.
            - attested_security_context:
                Attested security context:
                Represents a level of "trust" of
                the service containing a Level Of
                Agreement defined in the metadata
                of the Wallet Provider.
            - cnf:
                This parameter contains the jwk
                parameter
                with the public key of the Wallet
                necessary for the holder binding.
            - authorization_endpoint:
                URL of the OP's OAuth 2.0
                Authorization Endpoint.
            - response_types_supported:
                JSON array containing a list of
                the OAuth 2.0 response_type values
                that this OP supports.
            - vp_formats_supported:
                JSON object containing
                jwt_vp_json and jwt_vc_json
                supported algorithms array.
            - request_object_signing_alg_values_supported:
                JSON array containing a list of the
                JWS signing algorithms (alg values)
                supported by the OP for Request Objects.
            - presentation_definition_uri_supported:
                Boolean value specifying whether the
                Wallet Instance supports the transfer of
                presentation_definition by
                reference, with true indicating support.
    """
    header: create_model(header_model_name,
                         alg=(Literal[
                             "RS256",
                             "RS384",
                             "RS512",
                             "ES256",
                             "ES384",
                             "ES512",
                             "PS256",
                             "PS384",
                             "PS512",
                         ], ...),
                         typ=(Literal["wallet-attestation+jwt"], ...),
                         kid=(str, ...),
                         x5c=(list[str], ...),
                         trust_chain=(list[str], ...))

    payload: create_model(payload_model_name,
                          iss=(HttpUrl, ...),
                          sub=(str, ...),
                          iat=(int, ...),
                          exp=(int, ...),
                          type=(Literal["WalletInstanceAttestation"], ...),
                          policy_uri=(HttpUrl, ...),
                          tos_uri=(HttpUrl, ...),
                          logo_uri=(HttpUrl, ...),
                          attested_security_context=(HttpUrl, ...),
                          cnf=(create_model(cnf_model_name,
                                            jwk=(JwkSchema, ...),
                                            ), ...),
                          authorization_endpoint=(str, ...),
                          response_types_supported=(list[str], ...),
                          vp_formats_supported=(create_model(formats_supported_schema,
                                                             jwt_vp_json=(create_model(vp_model_name,
                                                                                       alg_values_supported=(
                                                                                           list[str], ...),
                                                                                       ), ...),
                                                             jwt_vc_json=(create_model(vp_model_name,
                                                                                       alg_values_supported=(
                                                                                           list[str], ...),
                                                                                       ), ...),
                                                             ), ...),
                          request_object_signing_alg_values_supported=(
                              list[str], ...),
                          presentation_definition_uri_supported=(bool, ...),
                          )
