import zlib
from binascii import hexlify
from binascii import unhexlify
from typing import Literal, Union, Tuple, Any
from typing import Optional

import cbor2
import pycose.algorithms
import pycose.keys.curves as curves
from pycose.headers import Algorithm, KID
from pycose.keys import CoseKey
from pycose.keys import EC2Key
from pycose.messages import Sign1Message

from pyeudiw.jwt.utils import base64_urldecode, base64_urlencode
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload

StatusListFormat = Literal["jwt", "cwt"]

STATUS_LIST_CWT = "application/statuslist+cwt"
STATUS_LIST_JWT = "application/statuslist+jwt"

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

def encode_cwt_status_list_token(payload_parts: Tuple[dict, dict, dict], bits: int, status_list: bytes,
                                 payload_map: dict | None = None, private_key: dict | None = None, ) -> bytes:
    """
    Encodes a CWT (CBOR Web Token) representing a status list with optional key signing.

    Args:
        payload_parts (Tuple[dict, dict, dict]): A tuple containing three dictionaries
            representing the protected header, unprotected header, and payload.
        bits (int): The number of bits representing the length of the status list.
        status_list (bytes): A byte string representing the status list bitstring.
        payload_map (dict | None): An optional dictionary mapping keys in the payload
            to their desired output names. If None, no mapping is applied.
        private_key (dict | None, optional): An optional dictionary representing the
            private key to sign the token. If None, the token is not signed.

    Returns:
        bytes: The encoded CWT token as a byte string.

    Note:
        The function applies `payload_map` recursively to the payload dictionary if provided,
        replacing keys according to the map.
    """
    # Compress the status list
    compressed_status_list = zlib.compress(status_list)

    # Insert the 'decoded_status_list' structure into the payload under claim key 65533
    payload = payload_parts[2]

    if payload_map:
        payload = _replace_keys(payload, payload_map)

    payload[65533] = {
        "bits": bits,
        "lst": compressed_status_list,
    }

    phdr = payload_parts[0]
    if 16 not in phdr:
        phdr[16] = STATUS_LIST_CWT
        if private_key:
            kid = bytes.fromhex(private_key["KID"].decode("utf-8"))
            phdr.setdefault(KID, kid)
            phdr.setdefault(Algorithm, pycose.algorithms.Es256)

    mso = Sign1Message(
        phdr=phdr,
        uhdr=payload_parts[1],
        payload=cbor2.dumps(payload, canonical=True)
    )
    if private_key:
        private_d = private_key["D"]
        kid = phdr[KID]
        if private_key["KTY"] == "EC2":
            mso.key = EC2Key(
                crv=getattr(curves, private_key["CURVE"].replace("_", ""), None),
                d=private_d,
                optional_params={"KID": kid}
            )
        else:
            mso.key = CoseKey.from_dict(private_key)

    return hexlify(mso.encode(
        tag=(private_key is not None),
        sign=(private_key is not None)
    ))

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
        header = _loads_cbor_data(data, 0)

        if header[16] != "application/statuslist+cwt":
            raise ValueError("Invalid token type")

        payload = _loads_cbor_data(data, 2)

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

def _replace_keys(input_dict: dict, field_map: dict) -> dict:
    """
   Recursively replaces keys in a dictionary according to a given mapping.

   Args:
       input_dict (dict): The input dictionary whose keys need to be replaced.
       field_map (dict): A mapping of original keys to their replacement keys.

   Returns:
       dict: A new dictionary with keys replaced based on `field_map`. If a key is
             not found in `field_map`, it remains unchanged. The function processes
             nested dictionaries recursively.

   Example:
       input_dict = {"name": "Alice", "info": {"age": 30, "city": "Rome"}}
       field_map = {"name": "fullName", "age": "years"}

       _replace_keys(input_dict, field_map)
       # Returns: {"fullName": "Alice", "info": {"years": 30, "city": "Rome"}}
   """
    return {field_map.get(k, k): (_replace_keys(v, field_map) if isinstance(v, dict) else v)
            for k, v in input_dict.items()}

def _loads_cbor_data(data: Any, index: int):
    """
    Load and decode CBOR data at a specific index from a list or CBOR tag container.

    This helper function handles both CBOR-encoded lists and CBOR tag objects with a `.value`
    attribute containing a list. It returns the decoded CBOR object at the specified index.

    Args:
        data (Any): A list of CBOR-encoded byte strings or a CBOR tag object with a `.value` attribute (e.g., `cbor2.CBORTag`).
        index (int): The index of the CBOR-encoded item to decode.

    Returns:
        Any: The Python object resulting from CBOR decoding the selected item.
    """
    if isinstance(data, list):
        return cbor2.loads(data[index])
    else:
        return cbor2.loads(data.value[index])