import json
import base64
from dataclasses import dataclass


from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from pyeudiw.federation.trust_chain.parse import get_public_key_from_trust_chain

from pyeudiw.jwt.utils import is_jwt_format
from pyeudiw.x509.verify import get_public_key_from_x509_chain
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload

KeyIdentifier_T = str


@dataclass(frozen=True)
class DecodedJwt:
    """
    Schema class for a decoded jwt.
    This class is not meant to be instantiated directly. Use instead
    the static method parse(str) -> DecodedJwt.
    """
    jwt: str
    header: dict
    payload: dict
    signature: str

    @staticmethod
    def parse(jws: str) -> 'DecodedJwt':
        return unsafe_parse_jws(jws)


def _unsafe_decode_part(part: str) -> dict:
    padding_needed = len(part) % 4
    if padding_needed:
        part += "=" * (4 - padding_needed)
    decoded_bytes = base64.urlsafe_b64decode(part)
    return json.loads(decoded_bytes.decode("utf-8"))


def unsafe_parse_jws(token: str) -> DecodedJwt:
    """
    Parse a token into its components.
    Correctness of this function is not guaranteed when the token is in a
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


def extract_key_identifier(token_header: dict) ->  ECKey | RSAKey | dict | KeyIdentifier_T:
    """
    Extracts the key identifier from the JWT header.
    The trust evaluation order might be mapped on the same configuration ordering.
    """
     # TODO: the trust evaluation order might be mapped on the same configuration ordering
    if "kid" in token_header.keys():
        return KeyIdentifier_T(token_header["kid"])
    if "trust_chain" in token_header.keys():
        return get_public_key_from_trust_chain(token_header["trust_chain"])
    if "x5c" in token_header.keys():
        return get_public_key_from_x509_chain(token_header["x5c"])
    raise ValueError(f"unable to infer identifying key from token head: searched among keys {token_header.keys()}")
