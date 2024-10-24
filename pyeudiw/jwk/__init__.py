from __future__ import annotations

import json
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import new_rsa_key

from .exceptions import InvalidKid, KidNotFoundError, InvalidJwk

KEY_TYPES_FUNC = dict(
    EC=new_ec_key,
    RSA=new_rsa_key
)


class JWK:
    """
    The class representing a JWK istance
    """

    def __init__(
        self,
        key: Union[dict, None] = None,
        key_type: str = "EC",
        hash_func: str = 'SHA-256',
        ec_crv: str = "P-256"
    ) -> None:
        """
        Creates an instance of JWK.

        :param key: An optional key in dict form.
        If no key is provided a randomic key will be generated.
        :type key: Union[dict, None]
        :param key_type: a string that represents the key type. Can be EC or RSA.
        :type key_type: str
        :param hash_func: a string that represents the hash function to use with the instance.
        :type hash_func: str
        :param ec_crv: a string that represents the curve to use with the instance.
        :type ec_crv: str

        :raises NotImplementedError: the key_type is not implemented
        """
        kwargs = {}
        self.kid = ""

        if key_type and not KEY_TYPES_FUNC.get(key_type, None):
            raise NotImplementedError(f"JWK key type {key_type} not found.")

        if key:
            if isinstance(key, dict):
                self.key = key_from_jwk_dict(key)
                key_type = key.get('kty', key_type)
                self.kid = key.get('kid', "")
            else:
                self.key = key
        else:
            # create new one
            if key_type in ['EC', None]:
                kwargs['crv'] = ec_crv
            self.key = KEY_TYPES_FUNC[key_type or 'EC'](**kwargs)

        self.thumbprint = self.key.thumbprint(hash_function=hash_func)
        self.jwk = self.key.to_dict()
        self.jwk["kid"] = self.kid or self.thumbprint.decode()
        self.public_key = self.key.serialize()
        self.public_key['kid'] = self.jwk["kid"]

    def as_json(self) -> str:
        """
        Returns the JWK in format of json string.

        :returns: A json string that represents the key.
        :rtype: str
        """
        return json.dumps(self.jwk)

    def export_private_pem(self) -> str:
        """
        Returns the JWK in format of a private pem certificte.

        :returns: A private pem certificate that represents the key.
        :rtype: str
        """
        _k = key_from_jwk_dict(self.jwk)
        pk = _k.private_key()
        pem = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem.decode()

    def export_public_pem(self) -> str:
        """
        Returns the JWK in format of a public pem certificte.

        :returns: A public pem certificate that represents the key.
        :rtype: str
        """
        _k = key_from_jwk_dict(self.jwk)
        pk = _k.public_key()
        cert = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cert.decode()

    def as_dict(self) -> dict:
        """
        Returns the JWK in format of dict.

        :returns: The key in form of dict.
        :rtype: dict
        """
        return self.jwk
    
    def as_public_dict(self) -> dict:
        """
        Returns the public key in format of dict.

        :returns: The public key in form of dict.
        :rtype: dict
        """
        return self.public_key

    def __repr__(self):
        # private part!
        return self.as_json()


class RSAJWK(JWK):
    def __init__(self, key: dict | None = None, hash_func: str = "SHA-256") -> None:
        super().__init__(key, "RSA", hash_func, None)


class ECJWK(JWK):
    def __init__(self, key: dict | None = None, hash_func: str = "SHA-256", ec_crv: str = "P-256") -> None:
        super().__init__(key, "EC", hash_func, ec_crv)


def jwk_form_dict(key: dict, hash_func: str = "SHA-256") -> RSAJWK | ECJWK:
    """
    Returns a JWK instance from a dict.

    :param key: a dict that represents the key.
    :type key: dict

    :returns: a JWK instance.
    :rtype: JWK
    """
    _kty = key.get('kty', None)

    if _kty is None or _kty not in ['EC', 'RSA']:
        raise InvalidJwk("Invalid JWK")
    elif _kty == "RSA":
        return RSAJWK(key, hash_func)
    else:
        ec_crv = key.get('crv', "P-256")
        return ECJWK(key, hash_func, ec_crv)


def find_jwk_by_kid(kid: str, jwks: list[dict], as_dict: bool = True) -> dict | JWK:
    """
    Find the JWK with the indicated kid in the jwks list.

    :param kid: the identifier of the jwk
    :type kid: str
    :param jwks: the list of jwks
    :type jwks: list[dict]
    :param as_dict: if True the return type will be a dict, JWK otherwise.
    :type as_dict: bool

    :raises InvalidKid: if kid is None.
    :raises KidNotFoundError: if kid is not in jwks list.

    :returns: the jwk with the indicated kid or an empty dict if no jwk is found
    :rtype: dict | JWK
    """
    if not kid:
        raise InvalidKid("Kid cannot be empty")
    for jwk in jwks:
        jwk_kid = jwk.get("kid", None)
        if jwk_kid and kid == jwk_kid:
            return jwk if as_dict else JWK(jwk)

    raise KidNotFoundError(f"Key with Kid {kid} not found")
