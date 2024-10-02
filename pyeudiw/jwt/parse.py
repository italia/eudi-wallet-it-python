from dataclasses import dataclass
from jwcrypto.common import base64url_decode, json_decode
from pyeudiw.federation.trust_chain.parse import get_public_key_from_trust_chain
from pyeudiw.jwk import JWK
from pyeudiw.jwt.utils import is_jwt_format
from pyeudiw.x509.verify import get_public_key_from_x509_chain

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


def _unsafe_decode_part(part: str) -> dict:
    return json_decode(base64url_decode(part))


def unsafe_parse_jws(token: str) -> DecodedJwt:
    """Parse a token into it's component.
    Correctness of this function  is not guaranteed when the token is in a
    derived format, such as sd-jwt and jwe.
    """
    if not is_jwt_format(token):
        raise ValueError(f"unable to parse {token}: not a jwt")
    b64header, b64payload, signature, *_ = token.split(".")
    head = {}
    payload = {}
    try:
        head = _unsafe_decode_part(b64header)
        payload = _unsafe_decode_part(b64payload)
    except Exception as e:
        raise ValueError(f"unable to decode JWS part: {e}")
    return DecodedJwt(token, head, payload, signature=signature)


def extract_key_identifier(token_header: dict) -> JWK | KeyIdentifier_T:
    if "trust_chain" in token_header.keys():
        return get_public_key_from_trust_chain(token_header["key"])
    if "x5c" in token_header.keys():
        return get_public_key_from_x509_chain(token_header["x5c"])
    if "kid" in token_header.keys():
        return KeyIdentifier_T(token_header["kid"])
    raise ValueError(f"unable to infer identifying key from token head: searched among keys {token_header.keys()}")
