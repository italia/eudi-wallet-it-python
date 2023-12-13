from pyeudiw.jwt.utils import decode_jwt_payload, decode_jwt_header
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt


class Vp(VpSdJwt):
    "Class for SD-JWT Format"
    def __init__(self, jwt: str) -> None:
        """
        Generates a VP istance.

        :param jwt: a string that represents the jwt.
        :type jwt: str

        :raises InvalidVPToken: if the jwt field's value is not a JWT.
        """
        super().__init__(jwt)

        self.parse_digital_credential()
        self.disclosed_user_attributes: dict = {}

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
        """
        Parse the digital credential of VP.
        
        :raises NotImplementedError: if VP Digital credentials type not implemented.
        """
        _typ = self._detect_vp_type()

        if _typ != 'jwt':
            raise NotImplementedError(
                f"VP Digital credentials type not implemented yet: {_typ}"
            )

        self.credential_headers = decode_jwt_header(self.payload['vp'])
        self.credential_payload = decode_jwt_payload(self.payload['vp'])

    @property
    def credential_issuer(self) -> str:
        """Returns the credential issuer"""
        if not self.credential_payload.get('iss', None):
            self.parse_digital_credential()
        return self.credential_payload.get('iss', None)