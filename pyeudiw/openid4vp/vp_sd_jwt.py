from typing import Dict
from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import is_jwt_format, decode_jwt_header, decode_jwt_payload
from pyeudiw.sd_jwt import verify_sd_jwt

from pyeudiw.jwk.exceptions import KidNotFoundError
from pyeudiw.openid4vp.vp import Vp

class VpSdJwt(Vp):
    """Class for SD-JWT Format"""

    def __init__(self, jwt: str):
        """
        Generates a VpSdJwt istance

        :param jwt: a string that represents the jwt.
        :type jwt: str

        :raises InvalidVPToken: if the jwt field's value is not a JWT.
        """

        super().__init__(jwt)

    def parse_digital_credential(self) -> None:
        """
        Parse the digital credential of VP.
        """

        self.credential_headers = decode_jwt_header(self.payload['vp'])
        self.credential_payload = decode_jwt_payload(self.payload['vp'])

    def verify(
        self,
        issuer_jwks_by_kid: Dict[str, dict] = {}
    ) -> bool:
        """
        Verifies a SDJWT.

        :param jwks_by_kids: a dictionary that contains one or more JWKs with the KID as the key.
        :type jwks_by_kids: Dict[str, dict]

        :raises KidNotFoundError: if the needed kid is not inside the issuer_jwks_by_kid.
        :raises NotImplementedError: the key_type of one or more JWK is not implemented.
        :raises JWSVerificationError: if self.jwt field is not in a JWS Format.

        :returns: True if is valid, False otherwise.
        """
        if not issuer_jwks_by_kid.get(self.credential_headers["kid"], None):
            raise KidNotFoundError(
                f"issuer jwks {issuer_jwks_by_kid} doesn't contain "
                f"the KID {self.credential_headers['kid']}"
            )

        issuer_jwk = JWK(issuer_jwks_by_kid[self.credential_headers["kid"]])
        holder_jwk = JWK(self.credential_payload["cnf"]["jwk"])

        # verify PoP
        jws = JWSHelper(holder_jwk)
        if not jws.verify(self.jwt):
            return False

        result = verify_sd_jwt(
            sd_jwt_presentation=self.payload["vp"],
            issuer_key=issuer_jwk,
            holder_key=holder_jwk
        )
        self.result = result

        # TODO: with unit tests we have holder_disclosed_claims while in
        # interop we don't have it!

        self.disclosed_user_attributes = result.get(
            "holder_disclosed_claims", result
        )

        # If IDA flatten the user attributes to be released
        if 'verified_claims' in result:
            result.update(result['verified_claims'].get('claims', {}))

        return True
