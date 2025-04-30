import uuid
from urllib.parse import quote_plus, urlencode

from pyeudiw.openid4vp.schemas.response import ResponseMode
from pyeudiw.presentation_definition.utils import DUCKLE_PRESENTATION, DUCKLE_QUERY_KEY
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
    authorization_config: dict,
    nonce: str = "",
    metadata: dict = None,
    submission_data: dict = None
) -> dict:
    """
    Primitive function to build the payload claims of the (JAR) authorization request.
    :param submission_data: data for manage custom claims in particular token
    :param client_id: the client identifier (who issue the jar token)
    :type client_id: str
    :param state: request session identifier
    :type state: str
    :param response_uri: endpoint accepting authorization responses
    :type response_uri: str
    :param authorization_config: backend configuration concerning \
        authorization request, should satisfy \
        pyeudiw.satosa.schemas.authorization.AuthorizationConfig
    :type authorization_config: dict
    :param nonce: optional nonce to be inserted in the request object; if not \
        set, a new cryptographically safe uuid v4 nonce is generated.
    :type nonce: str
    :param metadata: optional metadata to be included in the request object
    :type metadata: dict
    :raises KeyError: if authorization_config misses mandatory configuration options
    :returns: a dictionary with the *complete* set of jar jwt playload claims
    :rtype: dict
    """

    nonce = nonce or str(uuid.uuid4())
    if authorization_config.get("auth_iss_id"):
        _iss =  authorization_config["auth_iss_id"]
    else:
        _iss = client_id
        
    claims = {
        "client_id_scheme": "http",  # that's federation.
        "client_id": client_id,
        "response_mode": authorization_config.get(
            "response_mode", ResponseMode.direct_post_jwt
        ),
        "response_type": "vp_token",
        "response_uri": response_uri,
        "nonce": nonce,
        "state": state,
        "iss": _iss,
        "iat": iat_now(),
        "exp": exp_from_now(minutes=authorization_config["expiration_time"]),
    }

    if _aud := authorization_config.get("aud"):
        claims["aud"] = _aud

    if submission_data and submission_data["typo"] == DUCKLE_PRESENTATION:
        claims[DUCKLE_QUERY_KEY] = submission_data[DUCKLE_QUERY_KEY]
    else:
        if metadata:
            claims["client_metadata"] = metadata

        if authorization_config.get("scopes"):
            claims["scope"] = " ".join(authorization_config["scopes"])
        # backend configuration validation should check that at least PE or DCQL must be configured within the authz request conf
        if authorization_config.get("presentation_definition"):
            claims["presentation_definition"] = authorization_config[
                "presentation_definition"
            ]
    return claims
