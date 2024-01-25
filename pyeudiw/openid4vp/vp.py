from pyeudiw.openid4vp.exceptions import InvalidVPToken
from pyeudiw.jwt.utils import decode_jwt_payload, decode_jwt_header
from pyeudiw.tools.base_logger import BaseLogger
from pyeudiw.jwt.utils import is_jwt_format, decode_jwt_header, decode_jwt_payload


class Vp(BaseLogger):
    """Class for Verifiable Presentation istance."""

    def __init__(self, jwt: str) -> None:
        """
        Generates a VP istance.

        :param jwt: a string that represents the jwt.
        :type jwt: str

        :raises InvalidVPToken: if the jwt field's value is not a JWT.
        """

        if not is_jwt_format(jwt):
            raise InvalidVPToken("VP is not in JWT format.")

        self.headers = decode_jwt_header(jwt)
        self.jwt = jwt
        self.payload = decode_jwt_payload(jwt)

        self.credential_headers: dict = {}
        self.credential_payload: dict = {}

        self.parse_digital_credential()

        self.disclosed_user_attributes: dict = {}
        self._credential_jwks: list[dict] = []

    def _detect_vp_type(self) -> str:
        """
        Detects and return the type of verifiable presentation.

        :returns: the type of VP.
        :rtype: str
        """
        return self.headers["typ"].lower()

    def get_credential_jwks(self) -> list[dict]:
        """
        Returns the credential JWKs.

        :returns: the list containing credential's JWKs.
        :rtype: list[dict]
        """
        if not self.credential_jwks:
            return {}
        return self.credential_jwks

    def parse_digital_credential(self) -> None:
        raise NotImplementedError

    def set_credential_jwks(self, credential_jwks: list[dict]) -> None:
        """
        Set the credential JWKs for the current istance.

        :param credential_jwks: a list containing the credential's JWKs.
        :type credential_jwks: list[dict]
        """
        self._credential_jwks = credential_jwks

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

    @property
    def credential_jwks(self) -> list[dict]:
        """Returns the credential JWKs"""
        return self._credential_jwks

    @property
    def credential_issuer(self) -> str:
        """Returns the credential issuer"""
        if not self.credential_payload.get('iss', None):
            self.parse_digital_credential()
        return self.credential_payload.get('iss', None)
