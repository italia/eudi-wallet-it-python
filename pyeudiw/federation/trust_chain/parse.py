from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey


def get_public_key_from_trust_chain(trust_chain: list[str]) -> ECKey | RSAKey | dict:
    raise NotImplementedError("TODO")
