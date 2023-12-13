
from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWEHelper, JWSHelper
from pyeudiw.jwt.exceptions import JWEDecryptionError
from pyeudiw.jwk.exceptions import KidNotFoundError
from pyeudiw.jwt.utils import decode_jwt_header, is_jwe_format
from pyeudiw.openid4vp.exceptions import (
    VPNotFound,
    VPInvalidNonce,
    NoNonceInVPToken
)
from pyeudiw.openid4vp.schemas.vp_token import VPTokenPayload, VPTokenHeader
from pyeudiw.openid4vp.vp import Vp


class DirectPostResponse:
    def __init__(self, jwt: str, jwks_by_kids: dict, nonce: str = ""):

        self.headers = decode_jwt_header(jwt)
        self.jwks_by_kids = jwks_by_kids
        self.jwt = jwt
        self.nonce = nonce

        self._payload: dict = {}
        self._vps: list = []
        self.credentials_by_issuer: dict = {}
        self._claims_by_issuer: dict = {}

    def _decode_payload(self) -> None:

    def decrypt(self) -> None:
        _kid = self.headers.get('kid', None)
        if not _kid:
            raise KidNotFoundError(
                f"The JWT headers {self.headers} doesnt have any KID value"
            )
        self.jwk = JWK(self.jwks_by_kids[_kid])

        if is_jwe_format(self.jwt):
            jweHelper = JWEHelper(self.jwk)
            self._payload = jweHelper.decrypt(self.jwt)
        else:
            jwsHelper = JWSHelper(self.jwk)
            self._payload = jwsHelper.verify(self.jwt)

    def load_nonce(self, nonce: str):
        self.nonce = nonce

    def validate(self) -> bool:

        # check nonces
        for vp in self.get_presentation_vps():
            if self.nonce:
                if not vp.payload.get('nonce', None):
                    raise NoNonceInVPToken()

                if self.nonce != vp.payload['nonce']:
                    raise VPInvalidNonce(
                        "VP has a unknown nonce: "
                        f"{self.nonce} != {vp.payload['nonce']}"
                    )
            VPTokenPayload(**vp.payload)
            VPTokenHeader(**vp.headers)

        return True

    @property
    def vps(self):
        if not self._vps:
            self.get_presentation_vps()
        return self._vps

    def get_presentation_vps(self):
        if self._vps:
            return self._vps

        _vps = self.payload.get('vp_token', [])
        vps = [_vps] if isinstance(_vps, str) else _vps
        if not vps:
            raise VPNotFound("vp is null")

        for vp in vps:
            _vp = Vp(vp)
            self._vps.append(_vp)

            cred_iss = _vp.credential_payload['iss']
            if not self.credentials_by_issuer.get(cred_iss, None):
                self.credentials_by_issuer[cred_iss] = []

            self.credentials_by_issuer[cred_iss].append(_vp.payload['vp'])

        return self._vps

    @property
    def vps(self):
        if not self._vps:
            self.get_presentation_vps()
        return self._vps
    
    @property
    def payload(self) -> dict:
        if not self._payload:
            self._decode_payload()
        return self._payload