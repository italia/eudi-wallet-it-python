from typing import Any

from satosa.context import Context

from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.tools.mobile import is_smartphone


def detect_flow_typ(context: Context) -> RemoteFlowType:
    """
    Identitfy or guess the remote flow type based on the context of the
    user auhtnetication

    :param context: the context of the user authentication
    :type context: Context

    :returns: the remote flow type
    :rtype: RemoteFlowType
    """
    if is_smartphone(context.http_headers.get("HTTP_USER_AGENT")):
        return RemoteFlowType.SAME_DEVICE
    return RemoteFlowType.CROSS_DEVICE


def infer_vp_header_claim(jws: str, claim_name: str) -> Any:
    """
    Infer a claim from the header of a VP token.

    :param jws: the VP token
    :type jws: str

    :param claim_name: the name of the claim to infer
    :type claim_name: str

    :returns: the value of the claim
    :rtype: Any
    """
    headers = decode_jwt_header(jws)
    claim_value = headers.get(claim_name, "")
    return claim_value


def infer_vp_payload_claim(jws: str, claim_name: str) -> Any:
    """
    Infer a claim from the payload of a VP token.

    :param jws: the VP token
    :type jws: str

    :param claim_name: the name of the claim to infer
    :type claim_name: str

    :returns: the value of the claim
    :rtype: Any
    """
    headers = decode_jwt_payload(jws)
    claim_value: str = headers.get(claim_name, "")
    return claim_value
