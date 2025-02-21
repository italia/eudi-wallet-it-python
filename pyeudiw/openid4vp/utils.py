from typing import Any

from satosa.context import Context
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
