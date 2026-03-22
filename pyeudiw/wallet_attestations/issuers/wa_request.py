from functools import cached_property

from pyeudiw.wallet_attestations import (
    WalletInstanceAttestationRequestHeader,
    WalletInstanceAttestationRequestPayload,
)
from pyeudiw.wallet_attestations.issuers.base import BaseJwsIssuer


class WaJswRequestIssuer(BaseJwsIssuer):

    _JWT_TYPE = "attestations-request+jwt"

    def __init__(
        self,
        wallet_provider_id: str,
        hardware_priv_key: dict,  # wallet instance hardware keypair
        hardware_key_tag: str,  # wallet instance hardware keypair tag
        nonce: str,
        hardware_signature: str,
        integrity_assertion: str,
        attested_key,
    ):
        super().__init__(wallet_provider_id, hardware_priv_key)
        self._nonce = nonce
        self._hardware_signature = hardware_signature
        self._hardware_key_tag = hardware_key_tag
        self._integrity_assertion = integrity_assertion
        self._attested_key = attested_key

    @cached_property
    def _hardware_pubkey(self) -> dict:
        return self._private_jwk_to_pub(self._private_key)

    def _get_jwt_header(self) -> dict:
        claims = self._get_default_header_claims()
        WalletInstanceAttestationRequestHeader.model_validate(claims)
        return claims  # todo use model_dump

    def _get_jwt_payload(self) -> dict:
        claims = self._get_default_payload_claims()
        claims["iss"] = self._issuer + self._generate_jwk_thumbprint(
            self._hardware_pubkey
        )  # replace default
        claims["aud"] = self._issuer
        claims["nonce"] = self._nonce
        claims["hardware_signature"] = self._hardware_signature
        claims["integrity_assertion"] = self._integrity_assertion
        claims["attested_key"] = self._attested_key
        claims["hardware_key_tag"] = self._hardware_key_tag
        claims["cnf"] = dict(jwk=self._hardware_pubkey)
        WalletInstanceAttestationRequestPayload.model_validate(claims)
        return claims  # todo use model_dump
