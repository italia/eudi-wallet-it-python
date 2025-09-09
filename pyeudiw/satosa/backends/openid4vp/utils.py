import logging
import re
from typing import Optional, List

from satosa.context import Context

from pyeudiw.satosa.backends.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.tools.mobile import is_smartphone

logger = logging.getLogger(__name__)

def detect_flow_typ(context: Context,
                    force_same_device_flow_referer_criteria: Optional[List[str]] = None) -> RemoteFlowType:
    """
    Identify or guess the remote flow type based on the authentication context.

    Heuristics:
    - If the User-Agent clearly indicates a smartphone → SAME_DEVICE
    - If the request has sec-fetch-site == "cross-site" AND the Referer matches
      at least one of the regex patterns in referer_criteria → SAME_DEVICE
    - Otherwise → CROSS_DEVICE

    :param context: the context of the user authentication
    :type context: Context
    :param force_same_device_flow_referer_criteria: list of regex patterns (as strings) that, if matched
                             against the HTTP_REFERER header, indicate a wallet-originated request
    :type force_same_device_flow_referer_criteria: Optional[List[str]]
    :returns: the detected remote flow type
    :rtype: RemoteFlowType
    """
    if is_smartphone(context.http_headers.get("HTTP_USER_AGENT", "")):
        logger.info("Flow detected as SAME_DEVICE because User-Agent indicates smartphone.")
        return RemoteFlowType.SAME_DEVICE

    if (context.http_headers.get("HTTP_SEC_FETCH_SITE", "").lower() == "cross-site"
            and force_same_device_flow_referer_criteria):
        referer = context.http_headers.get("HTTP_REFERER", "")
        for pattern in force_same_device_flow_referer_criteria:
            if re.match(pattern, referer):
                logger.info(f"Flow detected as SAME_DEVICE because Referer '{referer}' matched regex '{pattern}'.")
                return RemoteFlowType.SAME_DEVICE

    logger.info("Flow classified as CROSS_DEVICE by default.")
    return RemoteFlowType.CROSS_DEVICE
