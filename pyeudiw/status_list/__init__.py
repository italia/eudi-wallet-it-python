import zlib
from binascii import hexlify
from binascii import unhexlify
from typing import Literal, Union
from typing import Tuple, Optional

import cbor2

from pyeudiw.jwt.utils import base64_urldecode, base64_urlencode
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload

StatusListFormat = Literal["jwt", "cwt"]

def decode_jwt_status_list_token(token: str) -> tuple[bool, dict, dict, int, bytes]:
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


def encode_cwt_status_list_token(
        payload_parts: Tuple[dict, dict, dict],
        bit_size: int = 1,
        status_list: Optional[bytes] = None
) -> bytes:
    """
    Encode a CWT status list token.

    :param payload_parts: A tuple (protected_header, unprotected_header, payload_dict).
    :type payload_parts: tuple[dict, dict, dict]
    :param bit_size: Number of bits in the status list (default: 1).
    :type bit_size: int
    :param status_list: Raw status list as bytes (optional).
    :type status_list: Optional[bytes]

    :return: The encoded CWT status list token (CBOR-encoded, hexlified).
    :rtype: bytes

    :raises ValueError: If no status list is provided via the payload or parameters.
    """
    protected_header, unprotected_header, payload_dict = payload_parts

    # Copy to avoid mutating the original
    payload_with_status_list = payload_dict.copy()

    # Handle embedded status list if present
    if "status_list" in payload_with_status_list:
        status_info = payload_with_status_list.pop("status_list")

        if not isinstance(status_info, dict) or "bits" not in status_info or "lst" not in status_info:
            raise ValueError("Invalid 'status_list' field: must contain 'bits' and 'lst'")

        status_bits = status_info["bits"]
        lst_raw = status_info["lst"]
        status_lst = zlib.compress(lst_raw if isinstance(lst_raw, bytes) else lst_raw.encode())

    elif status_list is not None:
        status_bits = bit_size
        status_lst = zlib.compress(status_list)
    else:
        raise ValueError("No status list found in payload and no external status_list provided.")

    # Set CBOR-specific key
    payload_with_status_list[65533] = {
        "bits": status_bits,
        "lst": status_lst
    }

    # Encode headers and payload
    encoded_protected = cbor2.dumps(protected_header)
    encoded_payload = cbor2.dumps(payload_with_status_list)

    # Wrap in CBOR tag for CWT
    cwt_array = [encoded_protected, unprotected_header, encoded_payload]
    tagged_cwt = cbor2.CBORTag(61, cwt_array)

    return hexlify(cbor2.dumps(tagged_cwt))


def decode_cwt_status_list_token(token: bytes) -> tuple[bool, dict, dict, int, bytes]:
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
    
def _compress_bitstring(bitstring: bytes) -> bytes:
    """
    Compress a bitstring using zlib.

    :param bitstring: The bitstring to compress.
    :type bitstring: bytes

    :return: The compressed bitstring.
    :rtype: bytes
    """
    compressed_data = zlib.compress(bitstring)
    return base64_urlencode(compressed_data)

def generate_status_list(
        bitstring: bytes, 
        bits: int = 1, 
        aggregation_uri: Optional[str] = None, 
        format: StatusListFormat = "jwt"
    ) -> Union[dict, bytes]:
    """
    Generate a status list.

    :param bitstring: The bitstring to generate the status list from.
    :type bitstring: bytes
    :param bits: The number of bits in the status list.
    :type bits: int
    :param aggregation_uri: The aggregation URI.
    :type aggregation_uri: Optional[str]
    :param format: The format of the status list, either "jwt" or "cwt".
    :type format: StatusListFormat

    :return: A dictionary containing the status list or a CWT token.
    :rtype: Union[dict, bytes]
    """
    compressed_status_list = _compress_bitstring(bitstring)
    
    status_list = {
        "bits": bits,
        "lst": compressed_status_list
    }

    if aggregation_uri:
        status_list["aggregation_uri"] = aggregation_uri

    if format == "jwt":
        return status_list

    return cbor2.dumps(status_list)

def array_to_bitstring(status_array: list[dict], bit_size: int = 1) -> bytes:
    """
    Convert an array of status objects to a bitstring.

    :param status_array: The array of status objects.
    :type status_array: list[dict]
    :param bit_size: The size of each bit in the bitstring.
    :type bit_size: int
    
    :return: The resulting bitstring.
    :rtype: bytes
    """

    status_array = sorted(status_array, key=lambda x: x["incremental_id"])

    bitstring: int = 0
    for status in status_array:
        if status["revoked"]:
            # Set bit to 1 if revoked
            bitstring |= 1 << (len(status_array) - status["incremental_id"])
        else:
            # Clear bit to 0 if not revoked
            bitstring &= ~(1 << (len(status_array) - status["incremental_id"]))

    bit_length = len(status_array)
    byte_length = (bit_length + 7) // 8
    return bitstring.to_bytes(byte_length, byteorder='big', signed=False)
