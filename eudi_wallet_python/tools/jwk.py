from enum import Enum
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.ec import new_ec_key, ECKey
from cryptojwt.jwk.rsa import new_rsa_key, RSAKey
from cryptography.hazmat.primitives import serialization

class KeyType(Enum):
    EC  = 1
    RSA = 2

class JWK():
    def __init__(self, key: str = None, keyType: KeyType = KeyType.EC, hash_func: str = None) -> None:
        if key:
            self.key = key 
        elif keyType == KeyType.EC:
            self.key = new_ec_key()
        else:
            self.key = new_rsa_key()
    
        self.thumbprint = key.thumbprint(hash_function=hash_func or 'SHA-256')
        self.jwk = key.to_dict()
        self.jwk["kid"] = self.thumbprint.decode()

    def as_dict(self):
        return self.jwk

    def export_public(self):
        _k = key_from_jwk_dict(self.jwk)
        jwk = _k.serialize()
        jwk["kid"] = self.jwk['kid']
        return jwk
    
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