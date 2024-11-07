from hashlib import sha256
import json
from typing import Any, Callable, TypeVar
import sd_jwt.common as sd_jwtcommon
from sd_jwt.common import SDJWTCommon

from pyeudiw.jwk import JWK
from pyeudiw.jwt.utils import base64_urldecode, base64_urlencode
from pyeudiw.jwt.verification import verify_jws_with_key
from pyeudiw.sd_jwt.exceptions import InvalidKeyBinding, UnsupportedSdAlg
from pyeudiw.sd_jwt.schema import is_sd_jwt_format, is_sd_jwt_kb_format, VerifierChallenge
from pyeudiw.jwt.parse import DecodedJwt
from pyeudiw.tools.utils import iat_now


_JsonTypes = dict | list | str | int | float | bool | None
_JsonTypes_T = TypeVar('_JsonTypes_T', bound=_JsonTypes)

DEFAULT_SD_ALG = "sha-256"
DIGEST_ALG_KEY = sd_jwtcommon.DIGEST_ALG_KEY
FORMAT_SEPARATOR = SDJWTCommon.COMBINED_SERIALIZATION_FORMAT_SEPARATOR
SD_DIGESTS_KEY = sd_jwtcommon.SD_DIGESTS_KEY
SD_LIST_PREFIX = sd_jwtcommon.SD_LIST_PREFIX

SUPPORTED_SD_ALG_FN: dict[str, Callable[[str], str]] = {
    "sha-256": lambda s: base64_urlencode(sha256(s.encode("ascii")).digest())
}


class SdJwt:
    """
    SdJwt is an utility class to easily parse and verify sd jwt.
    All class attributes are intended to be read only
    """

    def __init__(self, token: str):
        if not is_sd_jwt_format(token):
            raise ValueError(f"input [token]={token} is not an sd-jwt with: maybe it is a regular jwt?")
        self.token = token
        # precomputed values
        self.token_without_kb: str = ""
        self.issuer_jwt: DecodedJwt = DecodedJwt("", "", "", "")
        self.disclosures: list[str] = []
        self.holder_kb: DecodedJwt | None = None
        self._post_init_precomputed_values()

    def _post_init_precomputed_values(self):
        iss_jwt, *disclosures, kb_jwt = self.token.split(FORMAT_SEPARATOR)
        self.token_without_kb = iss_jwt + FORMAT_SEPARATOR + ''.join(disc + FORMAT_SEPARATOR for disc in disclosures)
        self.issuer_jwt = DecodedJwt.parse(iss_jwt)
        self.disclosures = disclosures
        if kb_jwt:
            self.holder_kb = DecodedJwt.parse(kb_jwt)
        # TODO: schema validations(?)

    def get_confirmation_key(self) -> dict:
        cnf: dict = self.issuer_jwt.payload.get("cnf", {}).get("jwk", {})
        if not cnf:
            raise ValueError("missing confirmation (cnf) key from issuer payload claims")
        return cnf

    def get_encoded_disclosures(self) -> list[str]:
        return self.disclosures

    def get_disclosed_claims(self) -> dict:
        return _extract_claims_from_payload(self.issuer_jwt.payload, self.disclosures, SUPPORTED_SD_ALG_FN[self.get_sd_alg()])

    def get_issuer_jwt(self) -> str:
        return self.issuer_jwt.jwt

    def get_holder_key_binding_jwt(self) -> str:
        return self.holder_kb.jwt

    def get_sd_alg(self) -> str:
        return self.issuer_jwt.payload.get("_sd_alg", DEFAULT_SD_ALG)

    def has_key_binding(self) -> bool:
        return self.holder_kb is not None

    def verify_issuer_jwt_signature(self, key: JWK) -> None:
        verify_jws_with_key(self.issuer_jwt.jwt, key)

    def verify_holder_kb_jwt(self, challenge: VerifierChallenge) -> None:
        """
        Checks validity of holder key binding.
        This procedure always passes when no key binding is used

        :raises UnsupportedSdAlg: if verification fails due to an unkown _sd_alg
        :raises InvalidKeyBinding: if the verification fails for a known reason
        """
        if not self.has_key_binding():
            return
        _verify_key_binding(self.token_without_kb, self.get_sd_alg(),
                            self.holder_kb, challenge)
        self.verify_holder_kb_jwt_signature()

    def verify_holder_kb_jwt_signature(self) -> None:
        if not self.has_key_binding():
            return
        cnf = self.get_confirmation_key()
        verify_jws_with_key(self.holder_kb.jwt, JWK(cnf))


class SdJwtKb(SdJwt):

    def __init__(self, token: str):
        if not is_sd_jwt_kb_format(token):
            raise ValueError(f"input [token]={token} is not an sd-jwt with key binding with: maybe it is a regular jwt?")
        super().__init__(token)
        if not self.holder_kb:
            raise ValueError("missing key binding jwt")


def _verify_challenge(hkb: DecodedJwt, challenge: VerifierChallenge):
    if (obt := hkb.payload.get("aud", None)) != (exp := challenge["aud"]):
        raise InvalidKeyBinding(f"challenge audience {exp} does not match obtained audience {obt}")
    if (obt := hkb.payload.get("nonce", None)) != (exp := challenge["nonce"]):
        raise InvalidKeyBinding(f"challenge nonce {exp} does not match obtained nonce {obt}")


def _verify_sd_hash(token_without_hkb: str, sd_hash_alg: str, expected_digest: str):
    hash_fn = SUPPORTED_SD_ALG_FN.get(sd_hash_alg, None)
    if not hash_fn:
        raise UnsupportedSdAlg(f"unsupported sd_alg: {sd_hash_alg}")
    if expected_digest != (obt_digest := hash_fn(token_without_hkb)):
        raise InvalidKeyBinding(f"sd-jwt digest {obt_digest} does not match expected digest {expected_digest}")


def _verify_iat(payload: dict) -> None:
    iat: int | None = payload.get("iat", None)
    if not isinstance(iat, int):
        raise ValueError("missing or invalid parameter [iat] in kbjwt")
    now = iat_now()
    if iat > now:
        raise InvalidKeyBinding("invalid parameter [iat] in kbjwt: issuance after present time")
    return


def _verify_key_binding(token_without_hkb: str, sd_hash_alg: str, hkb: DecodedJwt, challenge: VerifierChallenge):
    _verify_challenge(hkb, challenge)
    _verify_sd_hash(
        token_without_hkb, 
        sd_hash_alg, 
        hkb.payload.get("sd_hash",  "sha-256")
    )
    _verify_iat(hkb.payload)


def _disclosures_to_hash_mappings(disclosures: list[str], sd_alg: Callable[[str], str]) -> tuple[dict[str, str], dict[str, Any]]:
    """
    :returns: in order
        (i)  hash_to_disclosure, a map: digest -> raw disclosure (base64 encoded)
        (ii) hash_to_dec_disclosure, a map: digest -> decoded disclosure
    :rtype: tuple[dict[str, str], dict[str, Any]]
    """
    hash_to_disclosure: dict[str, str] = {}
    hash_to_dec_disclosure: dict[str, Any] = {}
    for disclosure in disclosures:
        decoded_disclosure = json.loads(base64_urldecode(disclosure).decode("utf-8"))
        digest = sd_alg(disclosure)
        if digest in hash_to_dec_disclosure:
            raise ValueError(f"duplicate disclosure for digest {digest}")
        hash_to_dec_disclosure[digest] = decoded_disclosure
        hash_to_disclosure[digest] = disclosure
    return hash_to_disclosure, hash_to_dec_disclosure


def _extract_claims_from_payload(payload: dict, disclosures: list[str], sd_alg: Callable[[str], str]) -> dict:
    hash_to_disclosure, hash_to_dec_disclosure = _disclosures_to_hash_mappings(disclosures, sd_alg)
    return _unpack_claims(payload, hash_to_dec_disclosure, sd_alg, [])


def _is_element_leaf(element: Any) -> bool:
    return (type(element) is dict and len(element) == 1 and SD_LIST_PREFIX in element
            and type(element[SD_LIST_PREFIX]) is str)


def _unpack_json_array(claims: list, decoded_disclosures_by_digest: dict[str, Any], sd_alg: Callable[[str], str], processed_digests: list[str]) -> list:
    result = []
    for element in claims:
        if _is_element_leaf(element):
            digest: str = element[SD_LIST_PREFIX]
            if digest in decoded_disclosures_by_digest:
                _, value = decoded_disclosures_by_digest[digest]
                result.append(_unpack_claims(value, decoded_disclosures_by_digest, sd_alg, processed_digests))
        else:
            result.append(_unpack_claims(element, decoded_disclosures_by_digest, sd_alg, processed_digests))
    return result


def _unpack_json_dict(claims: dict, decoded_disclosures_by_digest: dict[str, Any], sd_alg: Callable[[str], str], proceessed_digests: list[str]) -> dict:
    # First, try to figure out if there are any claims to be
    # disclosed in this dict. If so, replace them by their
    # disclosed values.
    filtered_unpacked_claims = {}
    for k, v in claims.items():
        if k != SD_DIGESTS_KEY and k != DIGEST_ALG_KEY:
            filtered_unpacked_claims[k] = _unpack_claims(v, decoded_disclosures_by_digest, sd_alg, proceessed_digests)

    for disclosed_digests in claims.get(SD_DIGESTS_KEY, []):
        if disclosed_digests in proceessed_digests:
            raise ValueError(f"duplicate hash found in SD-JWT: {disclosed_digests}")
        proceessed_digests.append(disclosed_digests)

        if disclosed_digests in decoded_disclosures_by_digest:
            _, key, value = decoded_disclosures_by_digest[disclosed_digests]
            if key in filtered_unpacked_claims:
                raise ValueError(
                        f"duplicate key found when unpacking disclosed claim: '{key}' in {filtered_unpacked_claims}; this is not allowed."
                    )
            unpacked_value = _unpack_claims(value, decoded_disclosures_by_digest, sd_alg, proceessed_digests)
            filtered_unpacked_claims[key] = unpacked_value
    return filtered_unpacked_claims


def _unpack_claims(claims: _JsonTypes_T, decoded_disclosures_by_digest: dict[str, Any],
                   sd_alg: Callable[[str], str], proceessed_digests: list[str]) -> _JsonTypes_T:
    if type(claims) is list:
        return _unpack_json_array(claims, decoded_disclosures_by_digest, sd_alg, proceessed_digests)
    elif type(claims) is dict:
        return _unpack_json_dict(claims, decoded_disclosures_by_digest, sd_alg, proceessed_digests)
    else:
        return claims
