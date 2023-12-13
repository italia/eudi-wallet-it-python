from .exceptions import InvalidVPToken
from pyeudiw.jwt.utils import decode_jwt_payload, decode_jwt_header, is_jwt_format
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt


class Vp(VpSdJwt):

    def __init__(self, jwt: str):
        super().__init__(jwt)

        self.parse_digital_credential()
        self.disclosed_user_attributes: dict = {}

    def _detect_vp_type(self):
        return self.headers["typ"].lower()

    def get_credential_jwks(self):
        if not self.credential_jwks:
            return {}
        return self.credential_jwks

    @property
    def credential_issuer(self):
        if not self.credential_payload.get('iss', None):
            self.parse_digital_credential()
        return self.credential_payload.get('iss', None)

    def parse_digital_credential(self):
        _typ = self._detect_vp_type()
        if _typ == 'jwt':
            self.credential_headers = decode_jwt_header(self.payload['vp'])
            self.credential_payload = decode_jwt_payload(self.payload['vp'])
        else:
            raise NotImplementedError(
                f"VP Digital credentials type not implemented yet: {_typ}"
            )
