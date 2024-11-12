from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.okp import OKPKey
from cryptojwt.jwk.hmac import SYMKey



def get_public_key_from_trust_chain(trust_chain: list[str]) ->  ECKey | RSAKey | OKPKey | SYMKey | dict:
    raise NotImplementedError("TODO")
