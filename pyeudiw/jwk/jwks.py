from pyeudiw.jwk import JWK
from pyeudiw.jwk.exceptions import InvalidKid, KidNotFoundError


def find_jwk_by_kid(jwks: list[dict], kid: str, as_dict: bool = True) -> dict | JWK:
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
        valid_jwk = jwk.get("kid", None)
        if valid_jwk and kid == valid_jwk:
            return jwk if as_dict else JWK(jwk)

    raise KidNotFoundError(f"Key with Kid {kid} not found")

def find_jwk_by_thumbprint(jwks: list[dict], thumbprint: bytes) -> dict | None:
    """Find if a jwk with the given thumbprint is part of the given JWKS.
    Function can be used to select if a public key without a kid (such as
    a key that is part of a certificate chain) is part of a jwk set.

    We assume that SHA-256 is the hash function used to produce the thumbprint.
    """
    for key in jwks:
        if JWK(key).thumbprint == thumbprint:
            return key
    return None
