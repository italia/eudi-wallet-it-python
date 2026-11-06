import hashlib
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


def openid4vp_handover_info_hash(
    client_id: str, nonce: str, jwk_thumbprint: bytes, response_uri: str
) -> bytes:
    """SHA-256 of the CBOR OpenID4VPHandoverInfo array."""
    encoded = cbor2.dumps([client_id, nonce, jwk_thumbprint, response_uri])
    return hashlib.sha256(encoded).digest()


def _transcript_parts(st: object) -> tuple:
    if isinstance(st, (list, tuple)) and len(st) == 3:
        return st[0], st[1], st[2]
    if isinstance(st, dict):
        return (
            _get_val(st, _ST_KEY_DEVICE_ENGAGEMENT),
            _get_val(st, _ST_KEY_EREADER),
            _get_val(st, _ST_KEY_HANDOVER),
        )
    raise MdocCborValidationError("invalid SessionTranscript in deviceSigned")


def _validate_session_transcript_openid4vp(
    st: object, expected_hash: bytes | None = None
) -> None:
    """Validate SessionTranscript conforms to OpenID4VP 1.0 appendix B.2.6.1."""
    dev_eng, ereader, handover = _transcript_parts(st)
    if dev_eng is not None:
        raise MdocCborValidationError(
            "SessionTranscript must have deviceEngagementBytes=null for OpenID4VP"
        )
    if ereader is not None:
        raise MdocCborValidationError(
            "SessionTranscript must have eReaderKeyBytes=null for OpenID4VP"
        )
    if (
        not isinstance(handover, (list, tuple))
        or len(handover) != 2
        or handover[0] != "OpenID4VPHandover"
        or not isinstance(handover[1], (bytes, bytearray))
    ):
        raise MdocCborValidationError(
            "SessionTranscript must include OpenID4VPHandover for OpenID4VP"
        )
    if expected_hash is not None and bytes(handover[1]) != expected_hash:
        raise MdocCborValidationError("OpenID4VPHandover does not match the request")


def _check_session_transcripts_in_mdoc(
    mdoc: MdocCbor, expected_hash: bytes | None = None
) -> None:
    """When deviceSigned contains SessionTranscript, validate OpenID4VP profile."""
    found = False
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
        if isinstance(st, (dict, list, tuple)):
            _validate_session_transcript_openid4vp(st, expected_hash)
            found = True
    if expected_hash is not None and not found:
        raise MdocCborValidationError(
            "SessionTranscript must include OpenID4VPHandover for OpenID4VP"
        )


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

    def validate(
        self,
        token: str,
        verifier_id: str,
        verifier_nonce: str,
        response_uri: str | None = None,
        jwk_thumbprint: bytes | None = None,
    ) -> None:
        mdoc = MdocCbor()
        mdoc.loads(data=token)

        if mdoc.verify() is False:
            raise MdocCborValidationError("Signature is invalid")

        expected_hash = None
        if response_uri and jwk_thumbprint is not None:
            expected_hash = openid4vp_handover_info_hash(
                verifier_id, verifier_nonce, jwk_thumbprint, response_uri
            )
        _check_session_transcripts_in_mdoc(mdoc, expected_hash)

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

        status = mdoc.status if isinstance(mdoc.status, dict) else None
        if not status or "status_list" not in status:
            raise VPRevoked("credential status list is missing")

        status_list = StatusListTokenHelper.from_status(status)
        if (
            status_list.is_expired()
            or status_list.get_status(status["status_list"]["idx"]) > 0
        ):
            raise VPRevoked("Status list indicates that the token is revoked")

    def parse(self, token: str) -> dict:
        mdoc = MdocCbor()
        mdoc.loads(data=token)
        mdoc.verify()

        return mdoc.disclosure_map
