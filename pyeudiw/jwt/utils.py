import base64
import json


def unpad_jwt_element(jwt: str, position: int) -> dict:
    b = jwt.split(".")[position]
    padded = f"{b}{'=' * divmod(len(b), 4)[1]}"
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data


def unpad_jwt_header(jwt: str) -> dict:
    return unpad_jwt_element(jwt, position=0)


def unpad_jwt_payload(jwt: str) -> dict:
    return unpad_jwt_element(jwt, position=1)


def get_jwk_from_jwt(jwt: str, provider_jwks: dict) -> dict:
    """
        docs here
    """
    head = unpad_jwt_header(jwt)
    kid = head["kid"]
    if isinstance(provider_jwks, dict) and provider_jwks.get('keys'):
        provider_jwks = provider_jwks['keys']
    for jwk in provider_jwks:
        if jwk["kid"] == kid:
            return jwk
    return {}
