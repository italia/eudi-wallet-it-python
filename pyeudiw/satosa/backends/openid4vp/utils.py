import logging
from typing import Optional, List

from satosa.context import Context

from pyeudiw.satosa.backends.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.tools.mobile import is_smartphone

logger = logging.getLogger(__name__)

def detect_flow_typ(context: Context, accepted_referers: Optional[List[str]] = None) -> RemoteFlowType:
    """
    Identify or guess the remote flow type based on the context of the
    user authentication.

    Heuristics:
    - If the User-Agent clearly indicates a smartphone → SAME_DEVICE
    - If the request has sec-fetch-site == "cross-site" AND the Referer matches one
      of the accepted_referers → SAME_DEVICE
    - Otherwise → CROSS_DEVICE

    :param context: the context of the user authentication
    :type context: Context
    :param accepted_referers: list of referer substrings that are trusted to
                              indicate a wallet-originated request
    :type accepted_referers: Optional[List[str]]
    :returns: the remote flow type
    :rtype: RemoteFlowType
    """
    if is_smartphone(context.http_headers.get("HTTP_USER_AGENT")):
        logger.info("Flow detected as SAME_DEVICE because User-Agent indicates smartphone.")
        return RemoteFlowType.SAME_DEVICE

    accepted_referers = accepted_referers or []
    referer = context.http_headers.get("HTTP_REFERER", "")
    if (context.http_headers.get("HTTP_SEC_FETCH_SITE", "").lower() == "cross-site"
            and any(r in referer for r in accepted_referers)):
        logger.info(f"Flow detected as SAME_DEVICE because Referer '{referer}' matched accepted list.")
        return RemoteFlowType.SAME_DEVICE

    logger.info("Flow defaulted to CROSS_DEVICE.")
    return RemoteFlowType.CROSS_DEVICE
