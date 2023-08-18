import cryptojwt
import json

from jwcrypto.common import base64url_encode

from binascii import unhexlify
from io import StringIO
from typing import Dict

from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.utils.yaml_specification import _yaml_load_specification
from sd_jwt.verifier import SDJWTVerifier

from pyeudiw.jwk import JWK
from pyeudiw.jwt import DEFAULT_SIG_KTY_MAP
from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.tools.utils import gen_exp_time, iat_now

from jwcrypto.jws import JWS
from json import dumps, loads

import jwcrypto


class TrustChainSDJWTIssuer(SDJWTIssuer):
    def __init__(self, user_claims: Dict, issuer_key, holder_key=None, sign_alg=None, add_decoy_claims: bool = True, serialization_format: str = "compact", additional_headers: dict = {}):
        self.additional_headers = additional_headers
        sign_alg = DEFAULT_SIG_KTY_MAP[issuer_key.kty]

        super().__init__(
            user_claims,
            issuer_key,
            holder_key,
            sign_alg,
            add_decoy_claims,
            serialization_format
        )

    def _create_signed_jws(self):
        self.sd_jwt = JWS(payload=dumps(self.sd_jwt_payload))

        _protected_headers = {"alg": self._sign_alg}
        if self.SD_JWT_HEADER:
            _protected_headers["typ"] = self.SD_JWT_HEADER

        for k, v in self.additional_headers.items():
            _protected_headers[k] = v

        # _protected_headers['kid'] = self._issuer_key['kid']
        self.sd_jwt.add_signature(
            self._issuer_key,
            alg=self._sign_alg,
            protected=dumps(_protected_headers),
        )

        self.serialized_sd_jwt = self.sd_jwt.serialize(
            compact=(self._serialization_format == "compact")
        )

        if self._serialization_format == "json":
            jws_content = loads(self.serialized_sd_jwt)
            jws_content[self.JWS_KEY_DISCLOSURES] = [
                d.b64 for d in self.ii_disclosures]
            self.serialized_sd_jwt = dumps(jws_content)


def _serialize_key(key, **kwargs):

    if isinstance(key, cryptojwt.jwk.rsa.RSAKey):
        key = key.serialize()
    elif isinstance(key, JWK):
        key = key.as_dict()
    elif isinstance(key, dict):
        pass
    else:
        key = {}
    return key


def pk_encode_int(i, bit_size=None):
    extend = 0
    if bit_size is not None:
        extend = ((bit_size + 7) // 8) * 2
    hexi = hex(i).rstrip("L").lstrip("0x")
    hexl = len(hexi)
    if extend > hexl:
        extend -= hexl
    else:
        extend = hexl % 2
    return base64url_encode(unhexlify(extend * '0' + hexi))


def import_pyca_pri_rsa(key, **params):
    pn = key.private_numbers()
    params.update(
        kty='RSA',
        n=pk_encode_int(pn.public_numbers.n),
        e=pk_encode_int(pn.public_numbers.e),
        d=pk_encode_int(pn.d),
        p=pk_encode_int(pn.p),
        q=pk_encode_int(pn.q),
        dp=pk_encode_int(pn.dmp1),
        dq=pk_encode_int(pn.dmq1),
        qi=pk_encode_int(pn.iqmp)
    )
    return jwcrypto.jwk.JWK(**params)


def _adapt_keys(issuer_key: JWK, holder_key: JWK):
    # _iss_key = issuer_key.key.serialize(private=True)
    # _iss_key['key_ops'] = 'sign'
    _issuer_key = import_pyca_pri_rsa(
        issuer_key.key.priv_key, kid=issuer_key.kid)

    holder_key = jwcrypto.jwk.JWK.from_json(
        json.dumps(_serialize_key(holder_key)))
    issuer_public_key = jwcrypto.jwk.JWK.from_json(_issuer_key.export_public())
    return dict(
        issuer_key=_issuer_key,
        holder_key=holder_key,
        issuer_public_key=issuer_public_key,
    )


def load_specification_from_yaml_string(yaml_specification: str):
    return _yaml_load_specification(StringIO(yaml_specification))


def issue_sd_jwt(specification: dict, settings: dict, issuer_key: JWK, holder_key: JWK, trust_chain: list[str] | None = None) -> str:
    claims = {
        "iss": settings["issuer"],
        "iat": iat_now(),
        "exp": gen_exp_time(settings["default_exp"])  # in seconds
    }

    specification.update(claims)
    use_decoys = specification.get("add_decoy_claims", True)
    adapted_keys = _adapt_keys(issuer_key, holder_key)

    additional_headers = {"trust_chain": trust_chain} if trust_chain else {}
    additional_headers['kid'] = issuer_key.kid

    sdjwt_at_issuer = TrustChainSDJWTIssuer(
        user_claims=specification,
        issuer_key=adapted_keys["issuer_key"],
        holder_key=adapted_keys["holder_key"],
        add_decoy_claims=use_decoys,
        additional_headers=additional_headers
    )

    return {"jws": sdjwt_at_issuer.serialized_sd_jwt, "issuance": sdjwt_at_issuer.sd_jwt_issuance}


def _cb_get_issuer_key(issuer: str, settings: dict, adapted_keys: dict):
    if issuer == settings["issuer"]:
        return adapted_keys["issuer_public_key"]
    else:
        raise Exception(f"Unknown issuer: {issuer}")


def verify_sd_jwt(sd_jwt_presentation: str, issuer_key: JWK, holder_key: JWK, settings: dict = {'default_exp': 60, 'key_binding': True}) -> dict:
    settings.update({"issuer": unpad_jwt_payload(sd_jwt_presentation)["iss"]})
    adapted_keys = {
        "issuer_key": jwcrypto.jwk.JWK(**issuer_key.as_dict()),
        "holder_key": jwcrypto.jwk.JWK(**holder_key.as_dict()),
        "issuer_public_key": jwcrypto.jwk.JWK(**issuer_key.as_dict())
    }
    serialization_format = "compact"
    sdjwt_at_verifier = SDJWTVerifier(
        sd_jwt_presentation,
        (lambda x: _cb_get_issuer_key(x, settings, adapted_keys)),
        None,
        None,
        serialization_format=serialization_format,
    )

    return sdjwt_at_verifier.get_verified_payload()
