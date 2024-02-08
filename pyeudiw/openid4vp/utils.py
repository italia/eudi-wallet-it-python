from pyeudiw.openid4vp.vp import Vp
from pyeudiw.openid4vp.vp_mdoc_cbor import VpMDocCbor
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt
from pyeudiw.jwt.utils import decode_jwt_header
from pyeudiw.openid4vp.exceptions import VPFormatNotSupported


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

    if headers["typ"].lower() == "jwt":
        return VpSdJwt(jwt)
    elif headers["typ"].lower() == "mdoc_cbor":
        return VpMDocCbor(jwt) 
    
    raise VPFormatNotSupported("VP Digital credentials type not implemented yet: {_typ}")
