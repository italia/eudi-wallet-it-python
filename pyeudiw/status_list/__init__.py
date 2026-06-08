import zlib
from binascii import hexlify, unhexlify
from typing import Any, Literal, Optional, Tuple, Union

import cbor2
import pycose.algorithms
import pycose.keys.curves as curves
from pycose.headers import KID, Algorithm
from pycose.keys import CoseKey, EC2Key
from pycose.messages import Sign1Message

from pyeudiw.jwt.utils import (
    base64_urldecode,
    base64_urlencode,
    decode_jwt_header,
    decode_jwt_payload,
)

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


def encode_cwt_status_list_token(
    payload_parts: Tuple[dict, dict, dict],
    bits: int,
    status_list: bytes,
    payload_map: dict | None = None,
    private_key: dict | None = None,
) -> bytes:
    """
    Encode a CWT representing a status list and optionally sign it.

    Compresses the status list and inserts it under claim 65533 in the payload; if
    a private_key is provided the token will be signed.

    :param payload_parts: A tuple containing the protected header, unprotected header, and payload.
    :type payload_parts: Tuple[dict, dict, dict]
    :param bits: The number of bits in the status list.
    :type bits: int
    :param status_list: The status list as a byte string.
    :type status_list: bytes
    :param payload_map: An optional mapping to replace keys in the payload.
    :type payload_map: dict | None
    :param private_key: An optional private key for signing the token.
    :type private_key: dict | None
    :return: The encoded CWT as a byte string.
    :rtype: bytes
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
            # kid = bytes.fromhex(private_key["KID"].decode("utf-8"))
            # phdr.setdefault(KID, kid)
            # phdr.setdefault(Algorithm, pycose.algorithms.Es256)
            kid = (
                private_key["KID"].encode("utf-8")
                if isinstance(private_key["KID"], str)
                else private_key["KID"]
            )
            phdr.setdefault(KID, kid)
            phdr.setdefault(Algorithm, pycose.algorithms.Es256)

    mso = Sign1Message(
        phdr=phdr, uhdr=payload_parts[1], payload=cbor2.dumps(payload, canonical=True)
    )
    if private_key:
        private_d = private_key["D"]
        kid = phdr[KID]
        if private_key["KTY"] == "EC2":
            mso.key = EC2Key(
                crv=getattr(curves, private_key["CURVE"].replace("_", ""), None),
                d=private_d,
                optional_params={"KID": kid},
            )
        else:
            mso.key = CoseKey.from_dict(private_key)

    return hexlify(
        mso.encode(tag=(private_key is not None), sign=(private_key is not None))
    )


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
    format: StatusListFormat = "jwt",
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

    status_list = {"bits": bits, "lst": compressed_status_list}

    if aggregation_uri:
        status_list["aggregation_uri"] = aggregation_uri

    if format == "jwt":
        return status_list

    return cbor2.dumps(status_list)

def array_to_bitstring_v1(status_array: list[dict], bits: int = 1) -> bytes:
    """
    Encode a list of credential status entries into a Token Status List byte array.

    Each entry is placed at the bit position equal to its ``incremental_id`` (the
    same value advertised as ``idx`` in the Referenced Token's ``status_list``
    claim), so the position the issuer writes is exactly the position a Relying
    Party reads with :meth:`StatusListTokenHelper.get_status`.

    Bits are packed least-significant-bit first within each byte, and bytes are
    in natural ascending order, per draft-ietf-oauth-status-list Section 4.1.

    :param status_array: status entries, each with ``incremental_id`` and ``revoked``.
    :type status_array: list[dict]
    :param bits: number of bits per status (one of 1, 2, 4, 8).
    :type bits: int

    :return: the uncompressed status list byte array.
    :rtype: bytes
    """

    if bits not in (1, 2, 4, 8):
        raise ValueError("Error: bits must be one of: 1, 2, 4, 8")

    entries = list(status_array)
    if not entries:
        return b""

    # Size the array to cover the highest index. Indexing by incremental_id
    # (rather than the dense enumeration order) keeps idx == bit position even
    # if some indices are absent from this snapshot.
    max_index = max(status["incremental_id"] for status in entries)
    total_bytes = (((max_index + 1) * bits) + 7) // 8
    buffer = bytearray(total_bytes)
    mask = (1 << bits) - 1

    for status in entries:
        index = status["incremental_id"]
        value = (1 if status["revoked"] else 0) & mask
        bit_position = index * bits
        buffer[bit_position // 8] |= value << (bit_position % 8)

    return bytes(buffer)


def array_to_bitstring(status_array: list[dict], bit_size: int = 1) -> bytes:
    """
    Convert an array of status objects to a bitstring.

    Thin wrapper around :func:`array_to_bitstring_v1` kept for backward
    compatibility; both produce the same least-significant-bit-first layout
    indexed by ``incremental_id``.

    :param status_array: The array of status objects.
    :type status_array: list[dict]
    :param bit_size: The size of each status in bits.
    :type bit_size: int

    :return: The resulting bitstring.
    :rtype: bytes
    """

    return array_to_bitstring_v1(status_array, bits=bit_size)


def _replace_keys(input_dict: dict, field_map: dict) -> dict:
    """
    Recursively replaces keys in a dictionary according to a given mapping.

    Args:
        input_dict (dict): The input dictionary whose keys need to be replaced.
        field_map (dict): A mapping of original keys to their replacement keys.

    Returns:
        dict: A new dictionary with keys replaced based on ``field_map``. If a key is
            not found in ``field_map``, it remains unchanged. The function processes
            nested dictionaries recursively.

    Example:
        input_dict = {"name": "Alice", "info": {"age": 30, "city": "Rome"}}
        field_map = {"name": "fullName", "age": "years"}

        _replace_keys(input_dict, field_map)
        # Returns: {"fullName": "Alice", "info": {"years": 30, "city": "Rome"}}
    """

    return {
        field_map.get(k, k): (_replace_keys(v, field_map) if isinstance(v, dict) else v)
        for k, v in input_dict.items()
    }


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
