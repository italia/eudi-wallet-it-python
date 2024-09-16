from pyeudiw.openid4vp.vp import Vp
from pyeudiw.openid4vp.vp_mdoc_cbor import VpMDocCbor
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
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

    # TODO: questo metodo è molto OOP old school e non mi piace per nulla.
    #  richiedere un po' di inversion of control perché scarica un sacco di oneri
    #  sull'interfaccia Vp che alla fine è definita un po' a caso. Forse dovrei
    #  rischrivere questa parte e basta
    # Ricorda giovane padawan: "accept interfaces, return structs", aka robustness principle

    # TODO: il parsing non dovrebbe essere fatto facendo inferenza sul
    #  jwt stesso, ma dovrebbe fare fede il format presente nella
    #  presentation submission. Questo problema è molto simile a quello precedente:
    #  se il caller sonoscesse (dalla submission) is type, non si ritroverebbe 
    #  a generare roba astratta
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


def infer_vp_typ(jws: str) -> str:
    headers = decode_jwt_header(jws)
    typ: str = headers.get("typ", "")
    return typ


def infer_vp_iss(jws: str) -> str:
    payload = decode_jwt_payload(jws)
    iss: str = payload.get("iss", "")
    return iss
