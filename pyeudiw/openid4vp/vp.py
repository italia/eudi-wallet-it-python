from pyeudiw.tools.base_logger import BaseLogger

JWT_TYPE = "JWT"
VC_SD_JWT_TYPE = "vc+sd-jwt"
WALLET_ATTESTATION_TYPE = "wallet-attestation+jwt"
MDOC_BCOR_TYPE = "mdoc_cbor"

SUPPORTED_VC_TYPES = (JWT_TYPE, VC_SD_JWT_TYPE, WALLET_ATTESTATION_TYPE, MDOC_BCOR_TYPE)


class Vp(BaseLogger):
    """Class for Verifiable Presentation istance."""

    def parse_digital_credential(self) -> None:
        raise NotImplementedError

    def _detect_vp_type(self) -> str:
        """
        Detects and return the type of verifiable presentation.

        :returns: the type of VP.
        :rtype: str
        """
        raise NotImplementedError

    def check_revocation(self):
        """
        Check if the VP is revoked.

        :raises RevokedVPToken: if the VP is revoked.
        """

        # TODO: check the revocation of the credential
        self._log_warning("VP", "Revocation check not implemented yet")

    def verify(self, **kwargs) -> bool:
        raise NotImplementedError
