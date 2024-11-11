# import json

# from jwcrypto.common import base64url_encode

# from binascii import unhexlify
# from io import StringIO
# from typing import Dict, Optional

# from pyeudiw.sd_jwt.issuer import SDJWTIssuer
# from pyeudiw.sd_jwt.utils.yaml_specification import _yaml_load_specification
# from pyeudiw.sd_jwt.verifier import SDJWTVerifier

# from pyeudiw.jwt import DEFAULT_SIG_KTY_MAP
# from pyeudiw.jwt.utils import decode_jwt_payload
# from pyeudiw.sd_jwt.exceptions import UnknownCurveNistName
# from pyeudiw.tools.utils import exp_from_now, iat_now

# # from jwcrypto.jws import JWS
# from cryptojwt.jws.jws import JWS
# from cryptojwt.jwk import JWK
# from json import dumps, loads

# # import jwcrypto
# # import jwcrypto.jwk

# from typing import Any
# from cryptojwt.jwk.ec import ECKey
# from cryptojwt.jwk.rsa import RSAKey
# from cryptojwt.jwk.okp import OKPKey
# from cryptojwt.jwk.hmac import SYMKey
# from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


# class TrustChainSDJWTIssuer(SDJWTIssuer):
#     """
#     Class for issue SD-JWT of TrustChain.
#     """

#     def __init__(
#         self,
#         user_claims: Dict[str, Any],
#         issuer_key: dict,
#         holder_key: dict | None = None,
#         sign_alg: str | None = None,
#         add_decoy_claims: bool = True,
#         serialization_format: str = "compact",
#         additional_headers: dict = {}
#     ) -> None:
#         """
#         Crate an instance of TrustChainSDJWTIssuer.

#         :param user_claims: the claims of the SD-JWT.
#         :type user_claims: dict
#         :param issuer_key: the issuer key.
#         :type issuer_key: dict
#         :param holder_key: the holder key.
#         :type holder_key: dict | None
#         :param sign_alg: the signing algorithm.
#         :type sign_alg: str | None
#         :param add_decoy_claims: if True add decoy claims.
#         :type add_decoy_claims: bool
#         :param serialization_format: the serialization format.
#         :type serialization_format: str
#         :param additional_headers: additional headers.
#         :type additional_headers: dict
#         """

#         self.additional_headers = additional_headers
#         sign_alg = sign_alg if sign_alg else DEFAULT_SIG_KTY_MAP[issuer_key.kty]
#         issuer_keys = [issuer_key]

#         super().__init__(
#             user_claims,
#             issuer_keys,
#             holder_key,
#             sign_alg,
#             add_decoy_claims,
#             serialization_format
#         )

#     def _create_signed_jws(self):
#         """
#         Creates the signed JWS.
#         """
#         self.sd_jwt = JWS(msg=self.sd_jwt_payload)

#         _protected_headers = {"alg": self._sign_alg}
#         if getattr(self, "SD_JWT_HEADER", None):
#             _protected_headers["typ"] = self.SD_JWT_HEADER

#         for k, v in self.additional_headers.items():
#             _protected_headers[k] = v

#         # _protected_headers['kid'] = self._issuer_key['kid']
#         self.sd_jwt.add_signature(
#             self._issuer_keys[0],
#             alg=self._sign_alg,
#             protected=dumps(_protected_headers),
#         )

#         self.serialized_sd_jwt = self.sd_jwt.serialize(
#             compact=(self._serialization_format == "compact")
#         )

#         if self._serialization_format == "json":
#             jws_content = loads(self.serialized_sd_jwt)
#             jws_content[self.JWS_KEY_DISCLOSURES] = [
#                 d.b64 for d in self.ii_disclosures]
#             self.serialized_sd_jwt = dumps(jws_content)
            
#     def issue_sd_jwt(
#     specification: Dict[str, Any],
#     settings: dict,
#     issuer_key: ECKey | RSAKey | OKPKey | SYMKey | dict ,
#     holder_key: ECKey | RSAKey | OKPKey | SYMKey | dict,
#     trust_chain: list[str] | None = None,
#     additional_headers: Optional[dict] = None
#     ) -> str:
#         """
#         Issue a SD-JWT.

#         :param specification: the specification of the SD-JWT.
#         :type specification: Dict[str, Any]
#         :param settings: the settings of the SD-JWT.
#         :type settings: dict
#         :param issuer_key: the issuer key.
#         :type issuer_key: JWK
#         :param holder_key: the holder key.
#         :type holder_key: JWK
#         :param trust_chain: the trust chain.
#         :type trust_chain: list[str] | None
#         :param additional_headers: use case specific header claims, such as 'typ'
#         :type additional_headers: dict

#         :returns: the issued SD-JWT.
#         :rtype: str
#         """

#         claims = {
#             "iss": settings["issuer"],
#             "iat": iat_now(),
#             "exp": exp_from_now(settings["default_exp"])  # in seconds
#         }

#         specification.update(claims)
#         use_decoys = specification.get("add_decoy_claims", True)
#         if additional_headers is None:
#             additional_headers = {}
#         if trust_chain:
#             additional_headers["trust_chain"] = trust_chain
#         additional_headers["kid"] = issuer_key.kid

#         sdjwt_at_issuer = TrustChainSDJWTIssuer(
#             user_claims=specification,
#             issuer_key=issuer_key,
#             holder_key=holder_key,
#             add_decoy_claims=use_decoys,
#             additional_headers=additional_headers
#         )

#         return {"jws": sdjwt_at_issuer.serialized_sd_jwt, "issuance": sdjwt_at_issuer.sd_jwt_issuance}


# def _serialize_key(
#     key: RSAKey | ECKey | JWK | dict,
#     **kwargs
# ) -> dict:
#     """
#     Serialize a key into dict.

#     :param key: the key to serialize.
#     :type key: RSAKey | ECKey | JWK | dict

#     :returns: the serialized key into a dict.
#     """
#     if isinstance(key, RSAKey) or isinstance(key, ECKey):
#         key = key.serialize()
#     elif isinstance(key, JWK):
#         key = key.as_dict()
#     elif isinstance(key, dict):
#         pass
#     else:
#         key = {}
#     return key


# def pk_encode_int(i: str, bit_size: int = None) -> str:
#     """
#     Encode an integer as a base64url string with padding.

#     :param i: the integer to encode.
#     :type i: str
#     :param bit_size: the bit size of the integer.
#     :type bit_size: int

#     :returns: the encoded integer.
#     :rtype: str
#     """

#     extend = 0
#     if bit_size is not None:
#         extend = ((bit_size + 7) // 8) * 2
#     hexi = hex(i).rstrip("L").lstrip("0x")
#     hexl = len(hexi)
#     if extend > hexl:
#         extend -= hexl
#     else:
#         extend = hexl % 2
#     return base64url_encode(unhexlify(extend * '0' + hexi))




# # def import_pyca_pri_rsa(key: RSAPrivateKey, **params) -> JWK:
# #     """
# #     Import a private RSA key from a PyCA object.

# #     :param key: the key to import.
# #     :type key: RSAKey | ECKey

# #     :raises ValueError: if the key is not a PyCA RSAKey object.

# #     :returns: the imported key.
# #     :rtype: RSAKey
# #     """

# #     if not isinstance(key, RSAPrivateKey):
# #         raise ValueError("key must be a ssl RSAPrivateKey object")

# #     pn = key.private_numbers()
# #     params.update(
# #         kty='RSA',
# #         n=pk_encode_int(pn.public_numbers.n),
# #         e=pk_encode_int(pn.public_numbers.e),
# #         d=pk_encode_int(pn.d),
# #         p=pk_encode_int(pn.p),
# #         q=pk_encode_int(pn.q),
# #         dp=pk_encode_int(pn.dmp1),
# #         dq=pk_encode_int(pn.dmq1),
# #         qi=pk_encode_int(pn.iqmp)
# #     )
# #     return jwcrypto.jwk.JWK(**params) #todo: not only rsa


# # def import_ec(key, **params):
# #     pn = key.private_numbers()
# #     curve_name = key.curve.name
# #     match curve_name:
# #         case "secp256r1":
# #             nist_name = "P-256"
# #         case "secp384r1":
# #             nist_name = "P-384"
# #         case "secp512r1":
# #             nist_name = "P-512"
# #         case _:
# #             raise UnknownCurveNistName(
# #                 f"Cannot translate {key.curve.name} into NIST name.")
# #     params.update(
# #         kty="EC",
# #         crv=nist_name,
# #         x=pk_encode_int(pn.public_numbers.x),
# #         y=pk_encode_int(pn.public_numbers.y),
# #         d=pk_encode_int(pn.private_value)
# #     )
# #     return jwcrypto.jwk.JWK(**params)


# # def _adapt_keys(issuer_key: JWK, holder_key: JWK) -> dict:
#     """
#     Adapt the keys to the SD-JWT library.

#     :param issuer_key: the issuer key.
#     :type issuer_key: JWK
#     :param holder_key: the holder key.
#     :type holder_key: JWK

#     :returns: the adapted keys as a dict.
#     :rtype: dict
#     """

#     # _iss_key = issuer_key.key.serialize(private=True)
#     # _iss_key['key_ops'] = 'sign'

#     match issuer_key.jwk["kty"]:
#         case "RSA":
#             _issuer_key = import_pyca_pri_rsa(
#                 issuer_key.key.priv_key, kid=issuer_key.kid)
#         case "EC":
#             _issuer_key = import_ec(
#                 issuer_key.key.priv_key, kid=issuer_key.kid)
#         case _:
#             raise KeyError(f"Unsupported 'kty' {issuer_key.key['kty']}")

#     holder_key = jwcrypto.jwk.JWK.from_json(
#         json.dumps(_serialize_key(holder_key)))
#     issuer_public_key = jwcrypto.jwk.JWK.from_json(_issuer_key.export_public())
#     return dict(
#         issuer_key=_issuer_key,
#         holder_key=holder_key,
#         issuer_public_key=issuer_public_key,
#     )


# # def load_specification_from_yaml_string(yaml_specification: str) -> dict:
# #     """
# #     Load a specification from a yaml string.

# #     :param yaml_specification: the yaml string.
# #     :type yaml_specification: str

# #     :returns: the specification as a dict.
# #     :rtype: dict
# #     """

# #     return _yaml_load_specification(StringIO(yaml_specification))







# def verify_sd_jwt(
#     sd_jwt_presentation: str,
#     issuer_key: JWK,
#     settings: dict = {'key_binding': True}
# ) -> (list | dict | Any):
#     """
#     Verify a SD-JWT.

#     :param sd_jwt_presentation: the SD-JWT to verify.
#     :type sd_jwt_presentation: str
#     :param issuer_key: the issuer key.
#     :type issuer_key: JWK
#     :param holder_key: the holder key.
#     :type holder_key: JWK
#     :param settings: the settings of SD-JWT.

#     :returns: the verified payload.
#     :rtype: list | dict | Any
#     """

#     settings.update(
#         {
#             "issuer": decode_jwt_payload(sd_jwt_presentation)["iss"]
#         }
#     )
#   

#     serialization_format = "compact"
#     sdjwt_at_verifier = SDJWTVerifier(
#         sd_jwt_presentation,
#         cb_get_issuer_key=(
#             lambda x, unverified_header_parameters: issuer_public_key
#         ),
#         expected_aud=None,
#         expected_nonce=None,
#         serialization_format=serialization_format,
#     )

#     return sdjwt_at_verifier.get_verified_payload()
