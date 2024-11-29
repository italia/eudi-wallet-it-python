from pyeudiw.jwk import JWK


def find_jwk_by_thumbprint(jwks: list[JWK], thumbprint: bytes) -> JWK | None:
    """Find if a jwk with the given thumbprint is part of the given JWKS.
    Function can be used to select if a public key without a kid (such as
    a key that is part of a certificate chain) is part of a jwk set.

    We assume that SHA-256 is the hash function used to profuce the thumbprint.
    """
    # TODO: unit test this function (this is important)
    for key in jwks:
        if key.thumbprint == thumbprint:
            return key
    return None
