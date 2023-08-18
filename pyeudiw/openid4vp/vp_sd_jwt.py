from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt import verify_sd_jwt


class VpSdJwt:

    def verify_sdjwt(
        self,
        issuer_jwks_by_kid: dict = {}
    ) -> dict:
        issuer_jwk = JWK(issuer_jwks_by_kid[self.credential_headers["kid"]])
        holder_jwk = JWK(self.credential_payload["cnf"]["jwk"])

        result = verify_sd_jwt(
            sd_jwt_presentation=self.payload["vp"],
            issuer_key=issuer_jwk,
            holder_key=holder_jwk
        )
        self.result = result
        self.disclosed_user_attributes = result["holder_disclosed_claims"]
        return True
