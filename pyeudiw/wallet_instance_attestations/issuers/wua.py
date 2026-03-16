from pyeudiw.wallet_instance_attestations.issuers.base import BaseJwsIssuer
from pyeudiw.wallet_instance_attestations.models.attestations import WalletUnitAttestationHeader, \
    WalletUnitAttestationPayload


class WuaJswIssuer(BaseJwsIssuer):

    _JWT_TYPE = "key-attestation+jwt"

    def __init__(self, issuer_id: str, provider_priv_key: dict, instance_pub_key: dict, x5c: list[str]):
        super().__init__(issuer_id, provider_priv_key)
        self._instance_pubkey = instance_pub_key
        self._x5c = x5c
        self._trust_chain = None
        self._certification = None
        self._status = None
        self._user_authentication = None
        self._key_storage = None
        self._attested_keys = None

    def set_trust_chain(self, chain: list[str]):
        self._trust_chain = chain

    def set_certification(self, cert_url: str):
        self._certification = cert_url

    def set_status(self, status: dict[str, dict]):
        self._status = status

    def set_user_authentication(self, user_authentication: list[str]):
        self._user_authentication = user_authentication

    def set_key_storage(self, key_storage: list[str]):
        self._key_storage = key_storage

    def set_attested_keys(self, attested_keys: list[dict]):
        self._attested_keys = attested_keys

    def _get_jwt_payload(self) -> dict:
        claims = self._get_default_payload_claims()
        claims["attested_keys"] = self._attested_keys
        claims["key_storage"] = self._key_storage
        claims["user_authentication"] = self._user_authentication
        claims["status"] = self._status
        claims["certification"] = self._certification
        WalletUnitAttestationPayload.model_validate(claims)
        return claims # todo use model_dump

    def _get_jwt_header(self) -> dict:
        claims = self._get_default_header_claims()
        claims["x5c"] = self._x5c
        if self._trust_chain is not None: claims["trust_chain"] = self._trust_chain
        WalletUnitAttestationHeader.model_validate(claims)
        return claims  # todo use model_dump
