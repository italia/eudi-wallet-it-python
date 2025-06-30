import uuid
from typing import Optional
from urllib.parse import quote_plus, urlencode

from pyeudiw.presentation_definition.utils import DUCKLE_PRESENTATION, DUCKLE_QUERY_KEY
from pyeudiw.satosa.backends.openid4vp.schemas.response import ResponseMode
from pyeudiw.tools.utils import exp_from_now, iat_now


def build_authorization_request_url(scheme: str, params: dict) -> str:
    """
    Build authorization request URL that let the wallet download the request
    object. This is loosely realted to RFC9101 [JAR], section 5.2.1.
    The scheme is either the scheme portion of a deeplink, such as "haip" or
    "eudiw", while params is a dictitonary of query parameters not urlencoded.
    """
    if "://" not in scheme:
        scheme = scheme + "://"
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
    :param client_id: the client identifier (who issue the jar token)
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
    :param nonce: optional nonce to be inserted in the request object; if not \
        set, a new cryptographically safe uuid v4 nonce is generated.
    :type nonce: str
    :param client_metadata: optional client_metadata to be included in the request object
    :type client_metadata: dict
    :param submission_data: optional submission data, such as the duckle query, \
        to be included in the request object.
        If this parameter is set, the duckle data is used to build the request object
        else the presentation definition retrocompatibility is used.
    :type submission_data: dict
    :param wallet_nonce: optional nonce to be used by the wallet.
    :type wallet_nonce: str
    :raises KeyError: if authorization_config misses mandatory configuration options
    :returns: a dictionary with the *complete* set of jar jwt playload claims
    :rtype: dict
    """

    nonce = nonce or str(uuid.uuid4())
    if default_claims.get("auth_iss_id"):
        _iss =  default_claims["auth_iss_id"]
    else:
        _iss = client_id
        
    claims = {
        "client_id_scheme": "http",  # that's federation.
        "client_id": client_id,
        "response_mode": default_claims.get(
            "response_mode", ResponseMode.direct_post_jwt
        ),
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
    else:
        if client_metadata:
            claims["client_metadata"] = client_metadata

        if default_claims.get("scopes"):
            claims["scope"] = " ".join(default_claims["scopes"])
        # backend configuration validation should check that at least PE or DCQL must be configured within the authz request conf
        if default_claims.get("presentation_definition"):
            claims["presentation_definition"] = default_claims[
                "presentation_definition"
            ]

    if wallet_nonce:
        claims["wallet_nonce"] = wallet_nonce

    return claims
