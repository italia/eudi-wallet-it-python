"""pycose compatibility with cbor2 >= 6.

cbor2 6 decodes fixed-length CBOR arrays as tuples and maps as frozendict;
pycose 1.1.0 expects lists and plain dicts. See
https://github.com/TimothyClaeys/pycose/issues/141
"""

from __future__ import annotations

import cbor2
from pycose.messages.cosemessage import CoseMessage

_APPLIED = False


def _mutable_dict(value):
    if type(value) is dict:
        return value
    try:
        return dict(value)
    except TypeError:
        return value


def _normalize_cose_obj(cose_obj):
    if isinstance(cose_obj, tuple):
        cose_obj = list(cose_obj)
    if isinstance(cose_obj, list) and len(cose_obj) > 1:
        cose_obj[1] = _mutable_dict(cose_obj[1])
    return cose_obj


def apply_pycose_cbor2_compat() -> None:
    """Patch CoseMessage.decode so tagged COSE arrays work with cbor2 6.x."""
    global _APPLIED
    if _APPLIED:
        return

    @classmethod
    def decode(cls, received, *args, **kwargs):
        try:
            cbor_msg = cbor2.loads(received)
            cbor_tag = cbor_msg.tag
            cose_obj = cbor_msg.value
        except AttributeError:
            raise AttributeError("Message was not tagged.")
        except ValueError:
            raise ValueError("Decode accepts only bytes as input.")

        cose_obj = _normalize_cose_obj(cose_obj)

        if isinstance(cose_obj, list):
            try:
                decoded = cls._COSE_MSG_ID[cbor_tag].from_cose_obj(
                    cose_obj, kwargs.get("allow_unknown_attributes", True)
                )
            except KeyError as e:
                raise KeyError("CBOR tag is not recognized", e) from e

            if not isinstance(decoded, cls):
                raise TypeError(
                    f"CBOR tag {cbor_tag} does not match the expected message type {cls.__name__}."
                )
            return decoded

        raise TypeError("Bytes cannot be decoded as COSE message")

    CoseMessage.decode = decode
    _APPLIED = True
