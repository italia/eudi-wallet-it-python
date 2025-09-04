import base64
import hashlib
import logging

from typing import Optional

from pyeudiw.jwk.exceptions import KidError
from pyeudiw.jwk.schemas.public import JwkSchema
from pyeudiw.jwt.jws_helper import JWSHelper

from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.oauth2.dpop.exceptions import InvalidDPoP, InvalidDPoPKid
from pyeudiw.oauth2.dpop.schema import DPoPTokenHeaderSchema, DPoPTokenPayloadSchema

logger = logging.getLogger(__name__)

class DPoPVerifier:
    """
    Helper class for validate DPoP proofs.
    """

    dpop_header_prefix = "DPoP "

    def __init__(
        self,
        http_header_dpop: str,
        http_header_authz: Optional[str] = None,
    ):
        """
        Generate an instance of DPoPVerifier.

        :param public_jwk: a dict representing the public JWK of DPoP.
        :type public_jwk: dict
        :param http_header_authz: a string representing the authz value.
        :type http_header_authz: Optional[str]
        :param http_header_dpop: a string representing the DPoP value.
        :type http_header_dpop: str

        :raises ValueError: if DPoP proof is not a valid JWT

        """

        self.dpop_authz_token = None

        if http_header_authz:
            self.dpop_authz_token = (
                http_header_authz.replace(self.dpop_header_prefix, "")
                if self.dpop_header_prefix in http_header_authz
                else http_header_authz
            )

        # If the jwt is invalid, this will raise an exception
        try:
            dpop_header = decode_jwt_header(http_header_dpop)
        except UnicodeDecodeError as e:
            logger.error("DPoP proof validation error, " f"{e.__class__.__name__}: {e}")
            raise ValueError("DPoP proof is not a valid JWT")
        except Exception as e:
            logger.error("DPoP proof validation error, " f"{e.__class__.__name__}: {e}")
            raise ValueError("DPoP proof is not a valid JWT")
        self.proof = http_header_dpop

        # If the jwk is invalid, raise an exception
        try:
            JwkSchema(**dpop_header.get("jwk", {}))
        except Exception as e:
            logger.error("Jwk validation error, " f"{e.__class__.__name__}: {e}")
            raise ValueError("JWK schema validation error during DPoP init")

        self.public_jwk = dpop_header["jwk"]

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
        
        try:
            jws_verifier.verify(self.proof)
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

        payload = decode_jwt_payload(self.proof)
        DPoPTokenPayloadSchema(**payload)

        if self.dpop_authz_token:
            _ath = hashlib.sha256(self.dpop_authz_token.encode())
            _ath_b64 = base64.urlsafe_b64encode(_ath.digest()).rstrip(b"=").decode()
            proof_valid = _ath_b64 == payload["ath"]

            return proof_valid
        
        return True
