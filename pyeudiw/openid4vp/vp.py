
from pyeudiw.jwt.utils import unpad_jwt_payload, unpad_jwt_header
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt


class Vp(VpSdJwt):

    def __init__(self, jwt: str):
        # TODO: what if the credential is not a JWT?
        self.headers = unpad_jwt_header(jwt)
        self.jwt = jwt
        self.payload = unpad_jwt_payload(jwt)

        self.credential_headers: dict = {}
        self.credential_payload: dict = {}

        self.parse_digital_credential()
        self.disclosed_user_attributes: dict = {}

    def _detect_vp_type(self):
        # TODO - automatic detection of the credential
        return 'jwt'

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

        if self._detect_vp_type() == 'jwt':
            self.credential_headers = unpad_jwt_header(self.payload['vp'])
            self.credential_payload = unpad_jwt_payload(self.payload['vp'])
        else:
            raise NotImplementedError(
                "VP Digital credentials type not implemented yet"
            )
