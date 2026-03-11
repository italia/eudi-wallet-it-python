import time
from functools import cached_property

from cryptojwt.jwk.jwk import key_from_jwk_dict
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.wallet_instance_attestation import WalletInstanceAttestationHeader, WalletInstanceAttestationPayload


class WiaIssuer:

    _WALLET_APP_ATTESTATION_TYPE = "oauth-client-attestation+jwt"

    def __init__(self, provider_id: str, provider_priv_key: dict, instance_pub_key: dict, x5c: list[str]):
        self._provider_id = provider_id
        self.__provider_priv_key = provider_priv_key
        self._instance_pubkey = instance_pub_key
        self._x5c = x5c

        self._wallet_link = None
        self._wallet_name = None
        self._status = None
        self._nbf_delta = None
        self._trust_chain = None

    @cached_property
    def _provider_priv_key(self) -> dict:
        _key = key_from_jwk_dict(self.__provider_priv_key)
        _key.alg = _key.alg or self._alg_from_jwk(self.__provider_priv_key)
        pub_key = _key.serialize(private=True)
        return pub_key

    @cached_property
    def _provider_pubkey(self) -> dict:
        _key = key_from_jwk_dict(self._provider_priv_key)
        _key.alg = _key.alg or self._alg_from_jwk(self._provider_priv_key)
        pub_key = _key.serialize(private=False)
        return pub_key

    @cached_property
    def _instance_pubkey_thumbprint(self) -> str:
        _key = key_from_jwk_dict(self._instance_pubkey)
        return _key.thumbprint("SHA-256").decode()

    def set_wallet_link(self, link):
        self._wallet_link = link

    def set_wallet_name(self, name):
        self._wallet_name = name

    def set_status(self, status: dict[str, dict]):
        self._status = status

    def set_nbf(self, sec_from_iat: int):
        """Seconds from iat to set NOTBEFORE . If not set, nbf is not included in the payload. Zero for nbf equal to iat."""
        if sec_from_iat is None or int(sec_from_iat) < 1:
            raise ValueError("sec_from_iat must be a positive integer or zero.")
        self._nbf_delta = sec_from_iat

    def set_trust_chain(self, chain: list[str]):
        self._trust_chain = chain

    def _build_header(self) -> dict:
        params = dict()
        params["kid"] = self._provider_pubkey.get("kid")
        params["alg"] = self._provider_pubkey.get("alg")
        params["typ"] = self._WALLET_APP_ATTESTATION_TYPE
        params["x5c"] = self._x5c
        WalletInstanceAttestationHeader.model_validate(params)
        return params


    def _build_payload(self, include_iat:bool=True, lifetime:int=86400) -> dict:
        params = dict()
        params["iss"] = self._provider_id
        iat = int(time.time())
        params["sub"] = self._instance_pubkey_thumbprint
        params["exp"] = iat + int(lifetime)
        params["cnf"] = dict(jwk=self._instance_pubkey)

        if include_iat: params["iat"] = iat
        if self._nbf_delta: params["nbf"] = iat + self._nbf_delta
        if self._wallet_link: params["wallet_link"] = self._wallet_link
        if self._wallet_name: params["wallet_name"] = self._wallet_name
        if self._status: params["status"] = self._status
        WalletInstanceAttestationPayload.model_validate(params)
        return params

    def generate_jwt(self, lifetime:int=86400, include_iat=True) -> str:
        header = self._build_header()
        payload = self._build_payload(include_iat=include_iat, lifetime=lifetime)

        # key_obj = key_from_jwk_dict(self._provider_priv_key)
        # _jws = JWS(json.dumps(payload), alg=header["alg"])
        # return _jws.sign_compact([key_obj], protected=header)

        jws_helper = JWSHelper([self._provider_priv_key])
        return jws_helper.sign(plain_dict=payload, protected=header)

    @staticmethod
    def _alg_from_jwk(jwk_key: dict) -> str | None:
        ec_mapping = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}

        kty = jwk_key.get("kty")
        if kty == "RSA":
            return "RS256"

        if kty == "EC":
            _crv = jwk_key.get("crv")
            return ec_mapping.get(jwk_key.get("crv"))
        return None
