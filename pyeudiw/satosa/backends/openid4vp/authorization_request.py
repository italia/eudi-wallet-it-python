import hashlib
import json
import uuid
from typing import Optional
from urllib.parse import quote_plus, urlencode

from pyeudiw.duckle_ql.utils import DUCKLE_PRESENTATION, DUCKLE_QUERY_KEY
from pyeudiw.satosa.backends.openid4vp.schemas.response import ResponseMode
from pyeudiw.tools.utils import exp_from_now, iat_now

CLIENT_ID_PREFIXES = ("openid_federation:", "x509_hash:")
_WALLET_SCHEMES = {
    "haip": "haip-vp",
    "haip-vp": "haip-vp",
    "openid4vp": "openid4vp",
}
RESPONSE_ENC_VALUES = ["A128GCM", "A256GCM"]
DEFAULT_RESPONSE_ENCRYPTION_KTY = "EC"
DEFAULT_RESPONSE_ENCRYPTION_CRV = "P-256"
DEFAULT_RESPONSE_ENCRYPTION_USE = "enc"
DEFAULT_RESPONSE_ENCRYPTION_ALG = "ECDH-ES"


def configured_response_mode(authorization: dict | None) -> str:
    mode = (authorization or {}).get("response_mode")
    if not mode:
        return ResponseMode.direct_post_jwt
    return mode


def response_encryption_key_params(config: dict) -> dict:
    jwt_conf = config.get("jwt") or {}
    return {
        "kty": jwt_conf.get("response_encryption_kty")
        or DEFAULT_RESPONSE_ENCRYPTION_KTY,
        "crv": jwt_conf.get("response_encryption_crv")
        or DEFAULT_RESPONSE_ENCRYPTION_CRV,
        "use": jwt_conf.get("response_encryption_use")
        or DEFAULT_RESPONSE_ENCRYPTION_USE,
        "alg": jwt_conf.get("default_enc_alg") or DEFAULT_RESPONSE_ENCRYPTION_ALG,
    }


def require_prefixed_client_id(client_id: str) -> str:
    if not isinstance(client_id, str) or not client_id.startswith(CLIENT_ID_PREFIXES):
        raise ValueError(
            "client_id must use the openid_federation or x509_hash prefix"
        )
    return client_id


def prefixed_client_id(config: dict) -> str:
    candidates: list[str] = []
    authorization = config.get("authorization") or {}
    metadata = config.get("metadata") or {}
    if authorization.get("client_id"):
        candidates.append(authorization["client_id"])
    if metadata.get("client_id"):
        candidates.append(metadata["client_id"])
    for trust in (config.get("trust") or {}).values():
        if not isinstance(trust, dict):
            continue
        client_id = (trust.get("config") or {}).get("client_id")
        if client_id:
            candidates.append(client_id)
    for client_id in candidates:
        if isinstance(client_id, str) and client_id.startswith(CLIENT_ID_PREFIXES):
            return client_id
    raise ValueError("client_id must use the openid_federation or x509_hash prefix")


def jwk_thumbprint_sha256(public_jwk: dict) -> bytes:
    """RFC 7638 SHA-256 thumbprint of an EC public JWK, as raw digest bytes."""
    required = {
        "crv": public_jwk["crv"],
        "kty": public_jwk["kty"],
        "x": public_jwk["x"],
        "y": public_jwk["y"],
    }
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def response_encryption_client_metadata(
    public_jwk: dict,
    vp_formats_supported: dict | None,
    use: str = DEFAULT_RESPONSE_ENCRYPTION_USE,
    alg: str = DEFAULT_RESPONSE_ENCRYPTION_ALG,
) -> dict:
    public = {
        claim: public_jwk[claim]
        for claim in ("kty", "crv", "x", "y", "kid")
        if claim in public_jwk
    }
    public["use"] = use
    public["alg"] = alg
    metadata = {
        "jwks": {"keys": [public]},
        "encrypted_response_enc_values_supported": list(RESPONSE_ENC_VALUES),
    }
    if vp_formats_supported:
        metadata["vp_formats_supported"] = vp_formats_supported
    return metadata


def build_authorization_request_url(scheme: str, params: dict) -> str:
    """
    Build the wallet invocation URL. The scheme is haip-vp or openid4vp.
    """

    if "://" not in scheme:
        scheme = _WALLET_SCHEMES.get(scheme, scheme) + "://"
    query_params = urlencode(params, quote_via=quote_plus)
    _sep = "" if "?" in scheme else "?"
    return f"{scheme}{_sep}{query_params}"


def build_authorization_request_claims(
    client_id: str,
    state: str,
    response_uri: str,
    default_claims: dict,
    nonce: str = "",
    client_metadata: Optional[dict] = None,
    submission_data: Optional[dict] = None,
    wallet_nonce: Optional[str] = None,
) -> dict:
    """
    Primitive function to build the payload claims of the (JAR) authorization request.

    :param client_id: the client identifier (who issues the JAR token)
    :type client_id: str
    :param state: request session identifier
    :type state: str
    :param response_uri: endpoint accepting authorization responses
    :type response_uri: str
    :param default_claims: a dictionary with the default claims to be used in the request object.
        It must contain the following mandatory keys:
        - "expiration_time": the expiration time in minutes of the request object
        - "response_mode": the response mode to be used in the request object
        - "auth_iss_id": the issuer identifier of the authorization server
        - "aud": the audience of the request object
    :type default_claims: dict
    :param nonce: optional nonce to be inserted in the request object; if not
        set, a new cryptographically safe uuid v4 nonce is generated.
    :type nonce: str
    :param client_metadata: optional client_metadata to be included in the request object
    :type client_metadata: dict
    :param submission_data: optional submission data, such as the duckle query,
        to be included in the request object.
        If this parameter is set, the duckle data is used to build the request object.
    :type submission_data: dict
    :param wallet_nonce: optional nonce to be used by the wallet.
    :type wallet_nonce: str
    :raises KeyError: if authorization_config misses mandatory configuration options
    :returns: a dictionary with the *complete* set of JAR JWT payload claims
    :rtype: dict
    """

    client_id = require_prefixed_client_id(client_id)
    nonce = nonce or str(uuid.uuid4())
    if default_claims.get("auth_iss_id"):
        _iss = default_claims["auth_iss_id"]
    else:
        _iss = client_id

    claims = {
        "client_id": client_id,
        "response_mode": configured_response_mode(default_claims),
        "response_type": "vp_token",
        "response_uri": response_uri,
        "nonce": nonce,
        "state": state,
        "iss": _iss,
        "iat": iat_now(),
        "exp": exp_from_now(minutes=default_claims["expiration_time"]),
    }

    if _aud := default_claims.get("aud", "https://self-issued.me/v2"):
        claims["aud"] = _aud

    if submission_data and submission_data["typo"] == DUCKLE_PRESENTATION:
        claims[DUCKLE_QUERY_KEY] = submission_data[DUCKLE_QUERY_KEY]
    if client_metadata:
        claims["client_metadata"] = client_metadata

    if wallet_nonce:
        claims["wallet_nonce"] = wallet_nonce

    return claims
