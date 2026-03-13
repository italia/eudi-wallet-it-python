import abc
import time

from functools import cached_property

from cryptojwt.jwk.jwk import key_from_jwk_dict

from pyeudiw.jwt.jws_helper import JWSHelper


class BaseJwsIssuer(abc.ABC):

    _DEFAULT_LIFETIME = 86400
    _JWT_TYPE = "jwt"

    def __init__(self, issuer: str, private_jwk: dict):
        self._issuer = issuer
        self.__private_jwk = private_jwk
        self._header = dict()
        self._payload = dict()
        self._lifetime = self._DEFAULT_LIFETIME


    @abc.abstractmethod
    def _get_jwt_header(self) -> dict:
        ...

    @abc.abstractmethod
    def _get_jwt_payload(self) ->  dict:
        ...

    @cached_property
    def _private_key(self) -> dict:
        _key = key_from_jwk_dict(self.__private_jwk)
        _key.alg = _key.alg or self._alg_from_jwk(self.__private_jwk)
        pub_key = _key.serialize(private=True)
        return pub_key

    def _get_default_header_claims(self) -> dict:
        """
        Return default jwt common header claims: kid, alg, typ
        """
        default_claims = dict()
        default_claims["kid"] = self._private_key.get("kid")
        default_claims["alg"] = self._private_key.get("alg")
        default_claims["typ"] = self._JWT_TYPE
        return default_claims

    def _get_default_payload_claims(self) -> dict:
        """
        Return default jwt common payload claims: iss, iat, exp
        """
        default_claims = dict()
        default_claims["iss"] = self._issuer
        iat = int(time.time())
        default_claims["iat"] = iat
        default_claims["exp"] = iat + int(self._lifetime)
        return default_claims

    def generate_jws(self, include_iat=True, lifetime: int=None) -> str|None:
        if lifetime is not None:
            self._lifetime = lifetime

        header = self._get_jwt_header()
        payload = self._get_jwt_payload()

        if not include_iat:
            if "iat" in payload: del payload["iat"]

        jws_helper = JWSHelper([self._private_key])
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

    @staticmethod
    def _private_jwk_to_pub(jwk_key: dict) -> dict:
        _key = key_from_jwk_dict(jwk_key)
        _key.alg = _key.alg or BaseJwsIssuer._alg_from_jwk(jwk_key)
        pub_key = _key.serialize(private=False)
        return pub_key

    @staticmethod
    def _generate_jwk_thumbprint(jwk_key: dict) -> str:
        _key = key_from_jwk_dict(jwk_key)
        return _key.thumbprint("SHA-256").decode()