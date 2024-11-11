from typing import Dict
from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.verification import verify_jws_with_key
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload, is_jwt_format


from pyeudiw.jwk.exceptions import KidNotFoundError
from pyeudiw.openid4vp.vp import Vp
from pyeudiw.openid4vp.exceptions import InvalidVPToken




class VpSdJwt(Vp):
    """Class for SD-JWT Format"""

    def __init__(self, jwt: str):
        """
        Generates a VP instance.

        :param jwt: a string that represents the jwt.
        :type jwt: str

        :raises InvalidVPToken: if the jwt field's value is not a JWT.
        """

        if not is_jwt_format(jwt):
            raise InvalidVPToken("VP is not in JWT format.")

        self.headers = decode_jwt_header(jwt)
        self.jwt = jwt
        self.payload = decode_jwt_payload(jwt)
        self.data = jwt
        self.credential_headers: dict = {}
        self.credential_payload: dict = {}

        self.parse_digital_credential()

        self.disclosed_user_attributes: dict = {}
        self._credential_jwks: list[dict] = []

    def parse_digital_credential(self) -> None:
        """
        Parse the digital credential of VP.
        """

        self.credential_headers = decode_jwt_header(self.payload['vp'])
        self.credential_payload = decode_jwt_payload(self.payload['vp'])

    def verify(
        self,
        **kwargs
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
        issuer_jwks_by_kid: Dict[str, dict] = kwargs.get(
            "issuer_jwks_by_kid", {})

        if not issuer_jwks_by_kid.get(self.credential_headers["kid"], None):
            raise KidNotFoundError(
                f"issuer jwks {issuer_jwks_by_kid} doesn't contain "
                f"the KID {self.credential_headers['kid']}"
            )

        issuer_jwk = issuer_jwks_by_kid[self.credential_headers["kid"]]
        holder_jwk = self.credential_payload["cnf"]["jwk"]

        # verify PoP
        jws = JWSHelper(holder_jwk)
        if not jws.verify(self.jwt):
            return False
    
        result = verify_jws_with_key(self.payload["vp"], issuer_jwk)
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

    def get_credential_jwks(self) -> list[dict]:
        """
        Returns the credential JWKs.

        :returns: the list containing credential's JWKs.
        :rtype: list[dict]
        """
        return self.credential_jwks or {}

    def set_credential_jwks(self, credential_jwks: list[dict]) -> None:
        """
        Set the credential JWKs for the current istance.

        :param credential_jwks: a list containing the credential's JWKs.
        :type credential_jwks: list[dict]
        """
        self._credential_jwks = credential_jwks

    def _detect_vp_type(self) -> str:
        """
        Detects and return the type of verifiable presentation.

        :returns: the type of VP.
        :rtype: str
        """
        return self.headers.get("typ", "").lower()

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
