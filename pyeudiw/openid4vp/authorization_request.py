from urllib.parse import quote_plus, urlencode
import uuid

from pyeudiw.openid4vp.schemas.response import ResponseMode
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


def build_authorization_request_claims(client_id: str, state: str, response_uri: str, authorization_config: dict) -> dict:
    """
    Primitive function to build the payload claims of the (JAR) authorization request.

    :param client_id: the client identifier (woh issue the jar token)
    :type client_id: str
    :param state: request session identifier
    :type state: str
    :param response_uri: endpoint accepting authorization responses
    :type response_uri: str
    :param authorization_config: backend configuration concerning \
        authorization request, should satisfy \
        pyeudiw.satosa.schemas.authorization.AuthorizationConfig
    :type authorization_config: dict
    :returns: a dictionary with the *complete* set of jar jwt playload claims
    :rtype: dict
    """
    claims = {
        "scope": ' '.join(authorization_config["scopes"]),
        "client_id_scheme": "entity_id",  # that's federation.
        "client_id": client_id,
        "presentation_definition": authorization_config["presentation_definition"],
        "response_mode": authorization_config.get("response_mode", ResponseMode.direct_post_jwt),
        "response_type": "vp_token",
        "response_uri": response_uri,
        "nonce": str(uuid.uuid4()),
        "state": state,
        "iss": client_id,
        "iat": iat_now(),
        "exp": exp_from_now(minutes=authorization_config["expiration_time"])
    }

    if (_aud := authorization_config.get("aud")):
        claims["aud"] = _aud
    return claims
