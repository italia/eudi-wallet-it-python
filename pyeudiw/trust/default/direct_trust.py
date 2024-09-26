from jwcrypto.jwk import JWK

from pyeudiw.trust.interface import IssuerTrustModel
from pyeudiw.vci.jwks_provider import VciJwksSource


class DirectTrustModel(IssuerTrustModel):

    def __init__(self, issuer_jwks_provider: VciJwksSource):
        self.issuer_jwks_provider = issuer_jwks_provider
        pass

    def get_verified_key(self, issuer: str, token_header: dict) -> JWK:
        kid: str = token_header.get("kid", None)
        if not kid:
            raise ValueError("missing claim [kid] in token header")
        jwks = self.issuer_jwks_provider.get_jwks(issuer)  # TODO: handle exception
        issuer_keys: list[dict] = jwks.get("keys", [])
        found_jwks: list[dict] = []
        for key in issuer_keys:
            obt_kid: str = key.get("kid", "")
            if kid == obt_kid:
                found_jwks.append(key)
        if len(found_jwks) != 1:
            raise ValueError(f"unable to uniquely identify a key with kid {kid} in appropriate section of issuer entity configuration")
        try:
            return JWK(**found_jwks[0])
        except Exception as e:
            raise ValueError(f"unable to parse issuer jwk: {e}")
