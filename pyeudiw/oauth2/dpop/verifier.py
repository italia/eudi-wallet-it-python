import base64
import hashlib
import logging

from pyeudiw.jwk.exceptions import KidError
from pyeudiw.jwk.schemas.public import JwkSchema
from pyeudiw.jwt.jws_helper import JWSHelper

from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.oauth2.dpop.exceptions import InvalidDPoP, InvalidDPoPAth, InvalidDPoPKid
from pyeudiw.oauth2.dpop.schema import DPoPTokenHeaderSchema, DPoPTokenPayloadSchema

logger = logging.getLogger(__name__)

class DPoPVerifier:
    """
    Helper class for validate DPoP proofs.
    """

    dpop_header_prefix = "DPoP "

    def __init__(
        self,
        public_jwk: dict,
        http_header_authz: str,
        http_header_dpop: str,
    ):
        """
        Generate an instance of DPoPVerifier.

        :param public_jwk: a dict representing the public JWK of DPoP.
        :type public_jwk: dict
        :param http_header_authz: a string representing the authz value.
        :type http_header_authz: str
        :param http_header_dpop: a string representing the DPoP value.
        :type http_header_dpop: str

        :raises ValueError: if DPoP proof is not a valid JWT

        """
        self.public_jwk = public_jwk
        self.dpop_token = (
            http_header_authz.replace(self.dpop_header_prefix, "")
            if self.dpop_header_prefix in http_header_authz
            else http_header_authz
        )
        # If the jwk is invalid, raise an exception
        try:
            JwkSchema(**public_jwk)
        except Exception as e:
            logger.error("Jwk validation error, " f"{e.__class__.__name__}: {e}")
            raise ValueError("JWK schema validation error during DPoP init")

        # If the jwt is invalid, this will raise an exception
        try:
            decode_jwt_header(http_header_dpop)
        except UnicodeDecodeError as e:
            logger.error("DPoP proof validation error, " f"{e.__class__.__name__}: {e}")
            raise ValueError("DPoP proof is not a valid JWT")
        except Exception as e:
            logger.error("DPoP proof validation error, " f"{e.__class__.__name__}: {e}")
            raise ValueError("DPoP proof is not a valid JWT")
        self.proof = http_header_dpop

    @property
    def is_valid(self) -> bool:
        """Returns True if DPoP is valid."""
        return self.validate()

    def validate(self) -> bool:
        """
        Validates the content of DPoP.

        :raises InvalidDPoPKid: if the kid of DPoP is invalid.
        :raises InvalidDPoPAth: if the header's JWK is different from public_jwk's one.

        :returns: True if the validation is correctly executed, False otherwise
        :rtype: bool
        """
        jws_verifier = JWSHelper(jwks=[self.public_jwk])
        dpop_valid = False
        try:
            dpop_data = jws_verifier.verify(self.proof)
            if dpop_data is not None:
                dpop_valid = True
        except KidError as e:
            raise InvalidDPoPKid(
                ("DPoP proof validation error, " f"kid does not match: {e}")
            )
        except Exception as e:
            raise InvalidDPoP(
                "DPoP proof validation error, " f"{e.__class__.__name__}: {e}"
            )

        header = decode_jwt_header(self.proof)
        DPoPTokenHeaderSchema(**header)

        if header["jwk"] != self.public_jwk:
            raise InvalidDPoPAth(
                (
                    "DPoP proof validation error,  "
                    "header['jwk'] != self.public_jwk, "
                    f"{header['jwk']} != {self.public_jwk}"
                )
            )

        payload = decode_jwt_payload(self.proof)
        DPoPTokenPayloadSchema(**payload)

        _ath = hashlib.sha256(self.dpop_token.encode())
        _ath_b64 = base64.urlsafe_b64encode(_ath.digest()).rstrip(b"=").decode()
        proof_valid = _ath_b64 == payload["ath"]
        
        return dpop_valid and proof_valid
