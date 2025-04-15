import zlib
import cbor2
from typing import Optional
from binascii import unhexlify
from pyeudiw.jwt.utils import base64_urldecode
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload

def _decode_jwt_status_list_token(token: str) -> tuple[bool, dict, dict, int, bytes]:
    """
    Decode a JWT status list token.

    :param token: The JWT status list token.
    :type token: str

    :return: A tuple containing the parsing status, the header, payload, bits, and status list.
    :rtype: tuple[dict, dict, int, bytes]
    """

    try:
        header = decode_jwt_header(token)

        if header["typ"] != "statuslist+jwt":
            raise ValueError("Invalid token type")
        
        payload = decode_jwt_payload(token)
        
        decoded_status_list = payload["status_list"]

        bits = decoded_status_list["bits"]

        compressed_data = base64_urldecode(decoded_status_list["lst"])
        status_list = zlib.decompress(compressed_data)

        return True, header, payload, bits, status_list
    except Exception:
        return False, {}, {}, 0, b""

def _decode_cwt_status_list_token(token: bytes) -> tuple[bool, dict, dict, int, bytes]:
    """
    Decode a CWT status list token.

    :param token: The CWT status list token.
    :type token: bytes

    :return: A tuple containing the parsing status, the header, payload, bits, and status list.
    :rtype: tuple[dict, dict, int, bytes]
    """

    try:

        data = cbor2.loads(unhexlify(token))
        header = cbor2.loads(data.value[0])

        if header[16] != "application/statuslist+cwt":
            raise ValueError("Invalid token type")
        
        payload = cbor2.loads(data.value[2])

        decoded_status_list = payload[65533]

        bits = decoded_status_list["bits"]
        status_list = zlib.decompress(decoded_status_list["lst"])

        return True, header, payload, bits, status_list
    except Exception:
        return False, {}, {}, 0, b""