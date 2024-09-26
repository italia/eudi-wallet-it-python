from jwcrypto.jwk import JWK


class IssuerTrustModel:

    def get_verified_key(issuer: str, token_header: dict) -> JWK:
        raise NotImplementedError
