from typing import Dict
from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWEHelper, JWSHelper
from pyeudiw.jwk.exceptions import KidNotFoundError
from pyeudiw.jwt.utils import decode_jwt_header, is_jwe_format
from pyeudiw.openid4vp.exceptions import (
    VPNotFound,
    VPInvalidNonce,
    NoNonceInVPToken
)
from pyeudiw.openid4vp.schemas.vp_token import VPTokenPayload, VPTokenHeader
from pyeudiw.openid4vp.vp import Vp
from pydantic import ValidationError


class DirectPostResponse:
    """
    Helper class for generate Direct Post Response.
    """
    def __init__(self, jwt: str, jwks_by_kids: Dict[str, dict], nonce: str = ""):
        """
        Generate an instance of DirectPostResponse.

        :param jwt: a string that represents the jwt.
        :type jwt: str
        :param jwks_by_kids: a dictionary that contains one or more JWKs with the KID as the key.
        :type jwks_by_kids: Dict[str, dict]
        :param nonce: a string that represents the nonce.
        :type nonce: str
        """
        self.headers = decode_jwt_header(jwt)
        self.jwks_by_kids = jwks_by_kids
        self.jwt = jwt
        self.nonce = nonce

        self._payload: dict = {}
        self._vps: list = []
        self.credentials_by_issuer: Dict[str, list[dict]] = {}
        self._claims_by_issuer: dict = {}

    def _decode_payload(self) -> None:
        """
        Internally decrypts the content of the JWT.

        :raises JWSVerificationError: if jws field is not in a JWS Format
        :raises JWEDecryptionError: if jwe field is not in a JWE Format
        """
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

    def load_nonce(self, nonce: str) -> None:
        """
        Load a nonce string inside the body of response.

        :param nonce: a string that represents the nonce.
        :type nonce: str
        """
        self.nonce = nonce

    def _validate_vp(self, vp: dict) -> bool:
        """
        Validate a single Verifiable Presentation.

        :param vp: the verifiable presentation to validate.
        :type vp: str

        :returns: True if is valid, False otherwhise.
        :rtype: bool
        """
        try:
            # check nonce
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
        except ValidationError as e:
            raise InvalidVPToken(
               f"VP is not valid, {e}: {vp.headers}.{vp.payload}"
            )
        return True
    

    def validate(self) -> bool:
        """
        Validates all VPs inside JWT's body.

        :returns: True if all VP are valid, False otherwhise.
        :rtype: bool
        """
        all_valid = None
        for vp in self.get_presentation_vps():
            try:
                self._validate_vp(vp)
                if all_valid == None:
                    all_valid = True
            except Exception as e:
                logger.error(
                    
                )
                all_valid = False
                
        return all_valid

    def get_presentation_vps(self) -> list[Vp]:
        """
        Returns the presentation's verifiable presentations.

        :raises VPNotFound: if no VPs are found.

        :returns: the list of vps.
        :rtype: list[dict]
        """
        if self._vps:
            return self._vps

        _vps = self.payload.get('vp_token', [])
        vps = [_vps] if isinstance(_vps, str) else _vps

        if not vps:
            raise VPNotFound(
                f'Vps are empty for response with nonce "{self.nonce}"'
            )

        for vp in vps:
            # TODO - add an exception handling here
            _vp = Vp(vp)
            self._vps.append(_vp)

            cred_iss = _vp.credential_payload['iss']
            if not self.credentials_by_issuer.get(cred_iss, None):
                self.credentials_by_issuer[cred_iss] = []
            self.credentials_by_issuer[cred_iss].append(_vp.payload['vp'])

        return self._vps

    @property
    def vps(self) -> list[dict]:
        """Returns the presentation's verifiable presentations"""
        if not self._vps:
            self.get_presentation_vps()
        return self._vps
    
    @property
    def payload(self) -> dict:
        """Returns the decoded payload of presentation"""
        if not self._payload:
            self._decode_payload()
        return self._payload
