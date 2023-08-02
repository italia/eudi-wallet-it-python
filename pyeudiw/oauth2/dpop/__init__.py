import hashlib
import logging
import uuid

from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import unpad_jwt_payload, unpad_jwt_header
from pyeudiw.jwk.exceptions import KidError
from pyeudiw.tools.utils import iat_now
from pyeudiw.oauth2.dpop.schema import (
    DPoPTokenHeaderSchema, DPoPTokenPayloadSchema)

logger = logging.getLogger("pyeudiw.oauth2.dpop")


class DPoPIssuer:
    def __init__(self, htu: str, token: str, private_jwk: dict):
        self.token = token
        self.private_jwk = private_jwk
        self.signer = JWSHelper(private_jwk)
        self.htu = htu

    @property
    def proof(self):
        data = {
            "jti": str(uuid.uuid4()),
            "htm": "GET",
            "htu": self.htu,
            "iat": iat_now(),
            "ath": hashlib.sha256(self.token.encode()).hexdigest()
        }
        jwt = self.signer.sign(
            data,
            protected={
                'typ': "dpop+jwt",
                'jwk': self.private_jwk.public_key
            }
        )
        return jwt


class DPoPVerifier:
    dpop_header_prefix = 'DPoP '

    def __init__(
        self,
        public_jwk: dict,
        http_header_authz: str,
        http_header_dpop: str,
    ):
        self.public_jwk = public_jwk
        self.dpop_token = (
            http_header_authz.replace(self.dpop_header_prefix, '')
            if self.dpop_header_prefix in http_header_authz
            else http_header_authz
        )
        # If the jwt is invalid, this will raise an exception
        try:
            unpad_jwt_header(http_header_dpop)
        except UnicodeDecodeError as e:
            logger.error(
                "DPoP proof validation error, "
                f"{e.__class__.__name__}: {e}"
            )
            raise ValueError("DPoP proof is not a valid JWT")
        except Exception as e:
            logger.error(
                "DPoP proof validation error, "
                f"{e.__class__.__name__}: {e}"
            )
            raise ValueError("DPoP proof is not a valid JWT")
        self.proof = http_header_dpop

    @property
    def is_valid(self):
        jws_verifier = JWSHelper(self.public_jwk)
        try:
            dpop_valid = jws_verifier.verify(self.proof)
        except KidError as e:
            logger.error(
                "DPoP proof validation error, "
                f"kid does not match: {e}"
            )
            return False
        except Exception as e:
            logger.error(
                "DPoP proof validation error, "
                f"{e.__class__.__name__}: {e}"
            )
            return False

        header = unpad_jwt_header(self.proof)
        DPoPTokenHeaderSchema(**header)

        if header['jwk'] != self.public_jwk:
            logger.error(
                "DPoP proof validation error,  "
                "header['jwk'] != self.public_jwk, "
                f"{header['jwk']} != {self.public_jwk}"
            )
            return False

        payload = unpad_jwt_payload(self.proof)
        DPoPTokenPayloadSchema(**payload)

        proof_valid = hashlib.sha256(
            self.dpop_token.encode()).hexdigest() == payload['ath']
        return dpop_valid and proof_valid
