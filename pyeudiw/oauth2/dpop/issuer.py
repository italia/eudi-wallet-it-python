import base64
import hashlib
import logging
import uuid

from typing import Optional
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.tools.utils import iat_now

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey

from cryptojwt.jwk.jwk import key_from_jwk_dict

logger = logging.getLogger(__name__)


class DPoPIssuer:
    """
    Helper class for generate DPoP proofs.
    """

    def __init__(self, htu: str, private_jwk: dict | ECKey | RSAKey, token: Optional[str] = None) -> None:
        """
        Generates an instance of DPoPIssuer.

        :param htu: a string representing the htu value.
        :type htu: str
        :param token: a string representing the token value.
        :type token: Optional[str]
        :param private_jwk: a dict representing the private JWK of DPoP.
        :type private_jwk: dict | ECKey | RSAKey
        """
        self.token = token
        self.htu = htu

        if isinstance(private_jwk, dict):
            self.private_jwk = key_from_jwk_dict(private_jwk)
        else:
            self.private_jwk = private_jwk

        self.signer = JWSHelper(self.private_jwk)

    @property
    def proof(self):
        """
        Generates and returns the DPoP proof.

        :returns: The DPoP proof as a JWT.
        :rtype: str
        """

        # Define the payload for the DPoP proof
        data = {
            "jti": str(uuid.uuid4()),
            "htm": "GET",
            "htu": self.htu,
            "iat": iat_now(),
        }

        if self.token:
            data["ath"] = base64.urlsafe_b64encode(
                hashlib.sha256(self.token.encode()).digest()
            ).rstrip(b"=").decode()

        jwt = self.signer.sign(
            data,
            protected={"typ": "dpop+jwt", "jwk": self.private_jwk.serialize()},
            kid_in_header=False,
        )
        return jwt
