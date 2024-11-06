from typing import Any

from satosa.context import Context

from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.openid4vp.vp import Vp
from pyeudiw.openid4vp.vp_mdoc_cbor import VpMDocCbor
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt
from pyeudiw.openid4vp.exceptions import VPFormatNotSupported
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.tools.mobile import is_smartphone


def identify_flow_typ(context: Context) -> RemoteFlowType:
    """
    Identitfy or guess the remote flow type based on the context of the
    user auhtnetication
    """
    if is_smartphone(context.http_headers.get('HTTP_USER_AGENT')):
        return RemoteFlowType.SAME_DEVICE
    return RemoteFlowType.CROSS_DEVICE


def vp_parser(jwt: str) -> Vp:
    """
    Handle the jwt returning the correct VP istance.

    :param jwt: a string that represents the jwt.
    :type jwt: str

    :raises VPFormatNotSupported: if the VP Digital credentials type is not implemented yet.

    :returns: the VP istance.
    :rtype: Vp
    """

    headers = decode_jwt_header(jwt)

    typ: str | None = headers.get("typ", None)
    if typ is None:
        raise ValueError("missing mandatory header [typ] in jwt header")

    match typ.lower():
        case "jwt":
            return VpSdJwt(jwt)
        case "vc+sd-jwt":
            raise NotImplementedError("parsing of vp tokens with typ vc+sd-jwt not supported yet")
        case "mcdoc_cbor":
            return VpMDocCbor(jwt)
        case unsupported:
            raise VPFormatNotSupported(f"parsing of unsupported vp typ [{unsupported}]")


def infer_vp_header_claim(jws: str, claim_name: str) -> Any:
    headers = decode_jwt_header(jws)
    claim_value = headers.get(claim_name, "")
    return claim_value


def infer_vp_payload_claim(jws: str, claim_name: str) -> Any:
    headers = decode_jwt_payload(jws)
    claim_value: str = headers.get(claim_name, "")
    return claim_value


def infer_vp_typ(jws: str) -> str:
    return infer_vp_header_claim(jws, claim_name="typ")


def infer_vp_iss(jws: str) -> str:
    return infer_vp_payload_claim(jws, claim_name="iss")
