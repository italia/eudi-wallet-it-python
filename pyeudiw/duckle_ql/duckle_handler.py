import base64
import json
from typing import Any, Optional

from cryptojwt import JWT
from cryptojwt.exception import BadSignature
from jose import JWTError, jwt
from jwcrypto.jwk import JWKSet, JWK

from pyeudiw.duckle_ql.processor import CriteriaProcessor
from pyeudiw.openid4vp.presentation_submission import BaseVPParser
from pyeudiw.trust.dynamic import CombinedTrustEvaluator, logger


def _decode_base64url(data: str) -> bytes:
    rem = len(data) % 4
    if rem > 0:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data)


def _extract_issuer_from_vp(decoded: dict) -> Optional[str]:
    return (
            decoded.get("iss")
            or decoded.get("holder")
            or decoded.get("credential", {}).get("issuer")
            or decoded.get("verifiableCredential", {}).get("issuer")
    )


def _is_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3


def _extract_payload(token: str) -> Optional[dict[str, Any]]:
    try:
        if _is_jwt(token):
            payload_b64 = token.split(".")[1]
            decoded_bytes = _decode_base64url(payload_b64)
            return json.loads(decoded_bytes)
        elif token.strip().startswith("{"):
            return json.loads(token)
    except Exception as e:
        raise ValueError(f"Extract payload failed: {e}")

class DuckleHandler(BaseVPParser):

    def __init__(self, trust_evaluator: CombinedTrustEvaluator, **config):
        super().__init__(trust_evaluator, **config)
        self.jwk_set = JWKSet()
        for key in config.get("public-keys", []):
            logger.debug("Add public-key: {}", key)
            self.jwk_set.add(JWK(**key))

        self.raw_criteria = config.get("criteria", [])
        self.criteria = CriteriaProcessor(self.raw_criteria).process()
        self.last_vp_token = None  # usato per parse() successivo

    def validate(self, token: str, verifier_id: str, verifier_nonce: str) -> bool:
        try:
            # JWT VP
            decoded = _extract_payload(token)
            if not decoded:
                return False

            issuer = _extract_issuer_from_vp(decoded)
            if not issuer or self.trust_evaluator.is_revoked(issuer):
                logger.warning("Failed to extract issuer from vp")
                return False

            if _is_jwt(token):
                unverified_header = json.loads(_decode_base64url(token.split(".")[0]).decode())
                typ = unverified_header.get("typ")

                if typ and "vp+jwt" in typ:
                    # JWT VC or VP
                    public_keys = self.trust_evaluator.get_public_keys(issuer)
                    jwt_decoder = JWT(key=public_keys, allowed_algs=["ES256", "RS256"])
                    decoded = jwt_decoder.unpack(token)

                    if decoded.get("nonce") and decoded["nonce"] != verifier_nonce:
                        return False

            if not self.criteria.validate(decoded):
                logger.warning("DCQL criteria not satisfied")
                return False

            self.last_vp_token = decoded
            return True

        except (BadSignature, Exception) as e:
            logger.error(f"Validation failed: {e}")
            return False

    def parse(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            if not header or 'kid' not in header:
                raise ValueError("Missing 'kid' (Key ID) in JWT header")

            # Step 2: Find the matching public key from the JWK set using the 'kid'
            kid = header['kid']
            if self.jwk_set['keys']:
                key = next((
                    JWK(**k).export(private_key=False)
                    for k in self.jwk_set['keys']
                    if k.get("kid") == kid
                ), None)
                if key is None:
                    raise ValueError(f"No matching key found for kid: {kid}")
            else:
                logger.warning("jwk_set.keys is empty, skipping kid check")
                key = None  # No signature check if keys are empty

            # Step 3: Decode and verify the JWT token
            options = {"verify_aud": False}
            if key is None:
                options["verify_signature"] = False

            payload = jwt.decode(
                token,
                key,
                algorithms=["ES256"],
                options=options
            )

            if "query" not in payload:
                raise ValueError("The token does not contain a DCQL query")

            return payload

        except JWTError as e:
            logger.error(f"JWT decoding error: {e}")
            raise ValueError(f"Failed to verify DCQL token: {e}")
        except Exception as e:
            logger.error(f"Parsing error: {e}")
            raise ValueError(f"An error occurred while parsing the token: {e}")
