from datetime import datetime, timezone

import cbor2
from cryptography.hazmat.primitives import serialization
from pymdoccbor.mdoc.verifier import MdocCbor

from pyeudiw.credential_presentation.base_vp_parser import BaseVPParser
from pyeudiw.satosa.backends.openid4vp.exceptions import (
    MdocCborValidationError,
    VPRevoked,
)
from pyeudiw.status_list.helper import StatusListTokenHelper
from pyeudiw.x509.verify import get_issuer_from_x5c

# ISO 18013-7 Annex B (OpenID4VP): SessionTranscript must have deviceEngagementBytes=null,
# eReaderKeyBytes=null, and handover with OpenID4VPHandover. CBOR map keys may be int or text.
_ST_KEY_DEVICE_ENGAGEMENT = ("deviceEngagementBytes", 0)
_ST_KEY_EREADER = ("eReaderKeyBytes", 1)
_ST_KEY_HANDOVER = ("handover", 2)


def _get_val(d: dict, keys: tuple) -> object:
    for k in keys:
        if k in d:
            return d[k]
    return None


def _validate_session_transcript_openid4vp(st: dict) -> None:
    """Validate SessionTranscript conforms to OpenID4VP profile (ISO 18013-7 Annex B)."""
    dev_eng = _get_val(st, _ST_KEY_DEVICE_ENGAGEMENT)
    ereader = _get_val(st, _ST_KEY_EREADER)
    handover = _get_val(st, _ST_KEY_HANDOVER)
    if dev_eng is not None:
        raise MdocCborValidationError(
            "SessionTranscript must have deviceEngagementBytes=null for OpenID4VP"
        )
    if ereader is not None:
        raise MdocCborValidationError(
            "SessionTranscript must have eReaderKeyBytes=null for OpenID4VP"
        )
    if handover is None:
        raise MdocCborValidationError(
            "SessionTranscript must include handover for OpenID4VP"
        )


def _check_session_transcripts_in_mdoc(mdoc: MdocCbor) -> None:
    """When deviceSigned contains SessionTranscript, validate OpenID4VP profile."""
    cdict = mdoc.data_as_cbor_dict
    for doc in cdict.get("documents", []):
        inner = doc.value if hasattr(doc, "value") else doc
        if not isinstance(inner, dict):
            continue
        ds = inner.get("deviceSigned", inner.get(2))
        if not ds:
            continue
        if isinstance(ds, bytes):
            try:
                ds = cbor2.loads(ds)
            except cbor2.CBORDecodeError:
                continue
        if not isinstance(ds, dict):
            continue
        st = ds.get("sessionTranscript", ds.get(0))
        if st is None:
            continue
        if isinstance(st, bytes):
            try:
                st = cbor2.loads(st)
            except cbor2.CBORDecodeError:
                raise MdocCborValidationError(
                    "invalid SessionTranscript in deviceSigned"
                )
        if isinstance(st, dict):
            _validate_session_transcript_openid4vp(st)


class VpMDocCbor(BaseVPParser):
    def _is_expired(self, mdoc: MdocCbor) -> bool:
        for document in mdoc.documents:
            try:
                if document.issuersigned.issuer_auth.payload_as_dict["validityInfo"][
                    "validUntil"
                ] < datetime.now(timezone.utc):
                    return True
            except KeyError:
                return True
        return False

    def validate(self, token: str, verifier_id: str, verifier_nonce: str) -> None:
        mdoc = MdocCbor()
        mdoc.loads(data=token)

        if mdoc.verify() is False:
            raise MdocCborValidationError("Signature is invalid")

        _check_session_transcripts_in_mdoc(mdoc)

        try:
            for document in mdoc.documents:
                x5c = [
                    cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
                    for cert in document.issuersigned.issuer_auth.x509_certificates
                ]

                self.trust_evaluator.get_public_keys(
                    get_issuer_from_x5c(x5c), {"x5c": x5c}
                )
        except Exception as e:
            raise MdocCborValidationError(f"Error validating keys: {e}")

        if self._is_expired(mdoc):
            raise MdocCborValidationError("Credential is expired")

        if mdoc.status:
            status_list = StatusListTokenHelper.from_status(mdoc.status)
            if (
                status_list.is_expired()
                or status_list.get_status(mdoc.status["status_list"]["idx"]) > 0
            ):
                raise VPRevoked("Status list indicates that the token is revoked")

    def parse(self, token: str) -> dict:
        mdoc = MdocCbor()
        mdoc.loads(data=token)
        mdoc.verify()

        return mdoc.disclosure_map
