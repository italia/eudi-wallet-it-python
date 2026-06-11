from functools import cached_property

from pyeudiw.wallet_attestations import (
    WalletInstanceAttestationHeader,
    WalletInstanceAttestationPayload,
)
from pyeudiw.wallet_attestations.issuers.base import BaseJwsIssuer


class WiaJswIssuer(BaseJwsIssuer):

    _JWT_TYPE = "oauth-client-attestation+jwt"

    def __init__(
        self,
        issuer_id: str,
        provider_priv_key: dict,
        instance_pub_key: dict,
        x5c: list[str],
    ):
        super().__init__(issuer_id, provider_priv_key)
        self._instance_pubkey = instance_pub_key
        self._x5c = x5c

        self._wallet_link = None
        self._wallet_name = None
        self._status = None
        self._nbf_delta = None
        self._trust_chain = None

    @cached_property
    def _instance_pubkey_thumbprint(self) -> str:
        return self._generate_jwk_thumbprint(self._instance_pubkey)

    def set_wallet_link(self, link):
        self._wallet_link = link

    def set_wallet_name(self, name):
        self._wallet_name = name

    def set_status(self, status: dict[str, dict]):
        self._status = status

    def set_nbf(self, sec_from_iat: int):
        """Seconds from iat to set NOTBEFORE . If not set, nbf is not included in the payload. Zero for nbf equal to iat."""
        if sec_from_iat is None or int(sec_from_iat) < 0:
            raise ValueError(
                "sec_from_iat must be a positive integer or zero."
            )  # todo move to model validator
        self._nbf_delta = sec_from_iat

    def set_trust_chain(self, chain: list[str]):
        self._trust_chain = chain

    def _get_jwt_header(self) -> dict:
        claims = self._get_default_header_claims()
        claims["x5c"] = self._x5c
        if self._trust_chain is not None:
            claims["trust_chain"] = self._trust_chain
        WalletInstanceAttestationHeader.model_validate(claims)
        return claims  # todo use model_dump

    def _get_jwt_payload(self) -> dict:
        claims = self._get_default_payload_claims()
        claims["sub"] = self._instance_pubkey_thumbprint
        claims["cnf"] = dict(jwk=self._instance_pubkey)

        if self._nbf_delta is not None:
            claims["nbf"] = claims["iat"] + self._nbf_delta
            claims["exp"] = claims["nbf"] + self._lifetime
        if self._wallet_link:
            claims["wallet_link"] = self._wallet_link
        if self._wallet_name:
            claims["wallet_name"] = self._wallet_name
        if self._status is not None:
            claims["status"] = self._status
        WalletInstanceAttestationPayload.model_validate(claims)
        return claims  # todo use model_dump
