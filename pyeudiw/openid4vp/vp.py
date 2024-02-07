from pyeudiw.tools.base_logger import BaseLogger

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

    def verify(
        self,
        **kwargs
    ) -> bool:
        raise NotImplementedError
