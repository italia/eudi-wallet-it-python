from pyeudiw.jwt.utils import base64_urldecode


def from_jwk_to_mso_mdoc_private_key(jwk_key: dict) -> dict:
    """
    Converts a JWK (JSON Web Key) EC private key to a format compatible with MSO/mDoc structures.

    This function transforms a JWK-style elliptic curve private key into a dictionary
    suitable for Mobile Security Object (MSO) or mdoc (mobile document) signing usage.
    It handles key type mapping, curve renaming, and base64url decoding of the private key value.
    """
    match jwk_key["kty"]:
        case "EC":
            kty_mso_mdoc = "EC2"
        case _:
            kty_mso_mdoc =jwk_key["kty"]

    mso_mdoc_private_key ={
        'KTY': kty_mso_mdoc,
        'CURVE': jwk_key["crv"].replace("-", "_"),
        'ALG': jwk_key["alg"],
        'D': base64_urldecode(jwk_key["d"]),
    }
    if jwk_key["kid"]:
        mso_mdoc_private_key["KID"] = jwk_key["kid"]
    return mso_mdoc_private_key