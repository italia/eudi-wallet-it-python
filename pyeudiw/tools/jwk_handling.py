from pyeudiw.jwk import JWK
from pyeudiw.openid4vp.interface import VpTokenParser
from pyeudiw.trust.interface import TrustEvaluator
from pyeudiw.jwk import find_jwk_by_kid

def find_vp_token_key(token_parser: VpTokenParser, key_source: TrustEvaluator) -> JWK:
    """
    :param token_parser: the token parser instance.
    :type token_parser: VpTokenParser
    :param key_source: the key source instance.
    :type key_source: TrustEvaluator

    :raises KidNotFoundError: if no key is found.
    :raises NotImplementedError: if the key is not in a comptible format.

    :returns: a JWK instance.
    :rtype: JWK
    """

    issuer = token_parser.get_issuer_name()
    trusted_pub_keys = key_source.get_public_keys(issuer)
    verification_key = token_parser.get_signing_key()

    if isinstance(verification_key, str):
        return find_jwk_by_kid(verification_key, trusted_pub_keys)
    
    if isinstance(verification_key, dict):
        raise NotImplementedError("TODO: matching of public key (ex. from x5c) with keys from trust source")
    
    raise Exception(f"invalid state: key with type {type(verification_key)}")
