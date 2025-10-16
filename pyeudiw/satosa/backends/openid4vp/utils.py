import logging
import re
from typing import Optional, List, Union

from satosa.context import Context

from pyeudiw.satosa.backends.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.tools.mobile import is_smartphone

logger = logging.getLogger(__name__)


def detect_flow_typ(
        context: Context,
        force_same_device_flow_referer_criteria: Optional[Union[bool, List[str]]] = None
) -> RemoteFlowType:
    """
    Identify or guess the remote flow type based on context and optional referer criteria.

    Logic:
    1. If `force_same_device_flow_referer_criteria` is True → force SAME_DEVICE
    2. If it's a list of regex patterns and any matches the Referer → SAME_DEVICE
    3. If User-Agent indicates smartphone → SAME_DEVICE
    4. Otherwise → CROSS_DEVICE

    Parameters
    ----------
    context : Context
        SATOSA context with HTTP headers.
    force_same_device_flow_referer_criteria : bool | list[str] | None
        - If True → forcibly classify as SAME_DEVICE
        - If list → check referer regex match
        - If None or False → evaluate normally

    Returns
    -------
    RemoteFlowType
        The detected remote flow type.
    """

    # Case 1: Forced SAME_DEVICE as boolean flag
    if isinstance(force_same_device_flow_referer_criteria, bool):
        if force_same_device_flow_referer_criteria:
            logger.info("Flow forced as SAME_DEVICE by boolean flag.")
            return RemoteFlowType.SAME_DEVICE

    # Case 2: Referer-based detection
    elif (isinstance(force_same_device_flow_referer_criteria, list)
          and force_same_device_flow(context, force_same_device_flow_referer_criteria)):
            return RemoteFlowType.SAME_DEVICE

    # Case 3: Smartphone detection
    if is_smartphone(context.http_headers.get("HTTP_USER_AGENT", "")):
        logger.info("Flow detected as SAME_DEVICE because User-Agent indicates smartphone.")
        return RemoteFlowType.SAME_DEVICE

    # Default case
    logger.info("Flow classified as CROSS_DEVICE by default.")
    return RemoteFlowType.CROSS_DEVICE

def force_same_device_flow(context: Context,
                           force_same_device_flow_referer_criteria: Optional[List[str]] = None) -> bool:
    """
    Determine if the configuration forces the use of SAME_DEVICE flow based on the presence of referer criteria.

    Parameters
    force_same_device_flow_referer_criteria: optional list of regex patterns (as strings) that, if provided, indicate a preference for SAME_DEVICE flow.

    Returns True if SAME_DEVICE flow is forced, False otherwise.
    """
    if force_same_device_flow_referer_criteria:
        referer = context.http_headers.get("HTTP_REFERER", "")
        for pattern in force_same_device_flow_referer_criteria:
            if re.search(pattern, referer):
                logger.info(f"Flow detected as SAME_DEVICE because Referer '{referer}' matched regex '{pattern}'.")
                return True
    else:
        logger.info("No referer criteria provided; defaulting to CROSS_DEVICE flow.")

    return False