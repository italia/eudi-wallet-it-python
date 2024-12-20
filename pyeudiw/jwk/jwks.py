from pyeudiw.jwk import JWK


def find_jwk_by_kid(jwks: list[dict], kid: str) -> dict | None:
    """Find the key with the indicated kid in the given jwks list.
    If multiple such keys are int he set, then the first found key
    will be returned.

    :param kid: the identifier of the jwk
    :type kid: str
    :param jwks: the list of jwks
    :type jwks: list[dict]

    :returns: the jwk with the indicated kid or None if the such key can be found
    :rtype: dict | None
    """
    if not kid:
        raise ValueError("kid cannot be empty")
    for jwk in jwks:
        obtained_kid = jwk.get("kid", None)
        if kid == obtained_kid:
            return jwk
    return None


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
