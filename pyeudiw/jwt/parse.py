from dataclasses import dataclass
from pyeudiw.federation.trust_chain.parse import get_public_key_from_trust_chain
from pyeudiw.jwk import JWK
from pyeudiw.jwt.utils import is_jwt_format
from pyeudiw.x509.verify import get_public_key_from_x509_chain
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload

KeyIdentifier_T = str


@dataclass(frozen=True)
class DecodedJwt:
    """
    Schema class for a decoded jwt.
    This class is not meant to be instantiated directly. Use instead
    the static metho parse(str) -> UnverfiedJwt
    """
    jwt: str
    header: dict
    payload: dict
    signature: str

    def parse(jws: str) -> 'DecodedJwt':
        return unsafe_parse_jws(jws)


def unsafe_parse_jws(token: str) -> DecodedJwt:
    """Parse a token into it's component.
    Correctness of this function  is not guaranteed when the token is in a
    derived format, such as sd-jwt and jwe.
    """
    if not is_jwt_format(token):
        raise ValueError(f"unable to parse {token}: not a jwt")
    
    try:
        head = decode_jwt_header(token)
        payload = decode_jwt_payload(token)
        signature = token.split(".")[2]
    except Exception as e:
        raise ValueError(f"unable to decode JWS part: {e}")
    return DecodedJwt(token, head, payload, signature=signature)


def extract_key_identifier(token_header: dict) -> JWK | KeyIdentifier_T:
    # TODO: the trust evaluation order might be mapped on the same configuration ordering
    if "kid" in token_header.keys():
        return KeyIdentifier_T(token_header["kid"])
    if "trust_chain" in token_header.keys():
        return get_public_key_from_trust_chain(token_header["trust_chain"])
    if "x5c" in token_header.keys():
        return get_public_key_from_x509_chain(token_header["x5c"])
    raise ValueError(f"unable to infer identifying key from token head: searched among keys {token_header.keys()}")
