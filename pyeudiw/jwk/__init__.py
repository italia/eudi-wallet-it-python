import json

from typing import Union
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.rsa import new_rsa_key
from cryptography.hazmat.primitives import serialization


KEY_TYPES_FUNC = dict(
    EC=new_ec_key,
    RSA=new_rsa_key
)


class JWK():
    def __init__(
        self,
        key: Union[dict, None] = None,
        key_type: str = "EC",
        hash_func: str = 'SHA-256',
        ec_crv: str = "P-256"
    ) -> None:

        kwargs = {}

        if key_type and not KEY_TYPES_FUNC.get(key_type, None):
            raise NotImplementedError(f"JWK key type {key_type} not found.")

        if key:
            if isinstance(key, dict):
                self.key = key_from_jwk_dict(key)
            else:
                self.key = key
        else:
            # create new one
            kwargs['crv'] = ec_crv
            self.key = KEY_TYPES_FUNC[key_type or 'EC'](**kwargs)

        self.thumbprint = self.key.thumbprint(hash_function=hash_func)
        self.jwk = self.key.to_dict()
        self.jwk["kid"] = self.thumbprint.decode()
        self.public_key = self.key.serialize()
        self.public_key['kid'] = self.jwk["kid"]

    def as_json(self):
        return json.dumps(self.jwk)

    def export_private_pem(self):
        _k = key_from_jwk_dict(self.jwk)
        pk = _k.private_key()
        pem = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem.decode()

    def export_public_pem(self):
        _k = key_from_jwk_dict(self.jwk)
        pk = _k.public_key()
        cert = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cert.decode()

    def as_dict(self):
        return self.jwk

    def __repr__(self):
        # private part!
        return self.as_json()
